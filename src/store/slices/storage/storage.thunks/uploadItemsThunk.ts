import { ActionReducerMapBuilder, createAsyncThunk } from '@reduxjs/toolkit';
import { items as itemUtils } from '@internxt/lib';

import i18n from '../../../../services/i18n.service';
import folderService from '../../../../services/folder.service';
import { renameFile } from '../../../../lib/utils';
import storageService from '../../../../services/storage.service';
import { DriveFileData, DriveItemData, UserSettings } from '../../../../models/interfaces';
import { taskManagerActions, taskManagerSelectors } from '../../task-manager';
import { storageActions, storageSelectors } from '..';
import { ItemToUpload } from '../../../../services/storage.service/storage-upload.service';
import { StorageState } from '../storage.model';
import { MAX_ALLOWED_UPLOAD_SIZE } from '../../../../lib/constants';
import { sessionSelectors } from '../../session/session.selectors';
import notificationsService, { ToastType } from '../../../../services/notifications.service';
import { RootState } from '../../..';
import errorService from '../../../../services/error.service';
import { TaskProgress, TaskStatus, TaskType, UploadFileTask } from '../../../../services/task-manager.service';
import { planThunks } from '../../plan';

interface UploadItemsThunkOptions {
  relatedTaskId: string;
  showNotifications: boolean;
  showErrors: boolean;
  onSuccess: () => void;
}

interface UploadItemsPayload {
  files: File[];
  parentFolderId: number;
  folderPath: string;
  options?: Partial<UploadItemsThunkOptions>;
}

const DEFAULT_OPTIONS: Partial<UploadItemsThunkOptions> = { showNotifications: true, showErrors: true };

/**
 * @description
 *  1. Prepare files to upload
 *  2. Schedule tasks
 */
export const uploadItemsThunk = createAsyncThunk<void, UploadItemsPayload, { state: RootState }>(
  'storage/uploadItems',
  async ({ files, parentFolderId, folderPath, options }: UploadItemsPayload, { getState, dispatch, requestId }) => {
    const user = getState().user.user as UserSettings;
    const showSizeWarning = files.some((file) => file.size >= MAX_ALLOWED_UPLOAD_SIZE);
    const isTeam: boolean = sessionSelectors.isTeam(getState());
    const filesToUpload: ItemToUpload[] = [];
    const errors: Error[] = [];
    const tasksIds: string[] = [];

    options = Object.assign(DEFAULT_OPTIONS, options || {});

    if (showSizeWarning) {
      notificationsService.show(
        'File too large.\nYou can only upload or download files of up to 1GB through the web app',
        ToastType.Warning,
      );
      return;
    }

    for (const [index, file] of files.entries()) {
      const { filename, extension } = itemUtils.getFilenameAndExt(file.name);
      const [parentFolderContentPromise, cancelTokenSource] = folderService.fetchFolderContent(parentFolderId);
      const taskId = `${requestId}-${index}`;
      const task: UploadFileTask = {
        id: taskId,
        relatedTaskId: options?.relatedTaskId,
        action: TaskType.UploadFile,
        status: TaskStatus.Pending,
        progress: TaskProgress.Min,
        fileName: filename,
        fileType: extension,
        isFileNameValidated: false,
        showNotification: !!options?.showNotifications,
        cancellable: true,
        stop: async () => cancelTokenSource.cancel(),
      };

      dispatch(taskManagerActions.addTask(task));

      const parentFolderContent = await parentFolderContentPromise;
      const [, , finalFilename] = itemUtils.renameIfNeeded(parentFolderContent.files, filename, extension);
      const fileContent = renameFile(file, finalFilename);

      dispatch(
        taskManagerActions.updateTask({
          taskId,
          merge: {
            fileName: finalFilename,
            isFileNameValidated: true,
          },
        }),
      );

      filesToUpload.push({
        name: finalFilename,
        size: file.size,
        type: extension,
        content: fileContent,
        parentFolderId,
        folderPath,
      });

      tasksIds.push(task.id);
    }

    // 2.
    for (const [index, file] of filesToUpload.entries()) {
      const taskId = tasksIds[index];
      const updateProgressCallback = (progress) => {
        const task = taskManagerSelectors.findTaskById(getState())(taskId);

        if (task?.status !== TaskStatus.Cancelled) {
          dispatch(
            taskManagerActions.updateTask({
              taskId: taskId,
              merge: {
                status: TaskStatus.InProcess,
                progress,
              },
            }),
          );
        }
      };
      const taskFn = async (): Promise<DriveFileData> => {
        const task = taskManagerSelectors.findTaskById(getState())(taskId);
        const [uploadFilePromise, actionState] = storageService.upload.uploadFile(
          user.email,
          file,
          isTeam,
          updateProgressCallback,
        );

        dispatch(
          taskManagerActions.updateTask({
            taskId,
            merge: {
              status: TaskStatus.Encrypting,
              stop: async () => {
                task?.stop?.();
                actionState?.stop();
              },
            },
          }),
        );

        const uploadedFile = await uploadFilePromise;

        uploadedFile.name = file.name;

        return uploadedFile;
      };

      file.parentFolderId = parentFolderId;

      await taskFn()
        .then((uploadedFile) => {
          const currentFolderId = storageSelectors.currentFolderId(getState());

          if (uploadedFile.folderId === currentFolderId) {
            dispatch(
              storageActions.pushItems({
                updateRecents: true,
                folderIds: [currentFolderId],
                items: uploadedFile as DriveItemData,
              }),
            );
          }

          dispatch(
            taskManagerActions.updateTask({
              taskId: taskId,
              merge: { status: TaskStatus.Success },
            }),
          );
        })
        .catch((err: unknown) => {
          const castedError = errorService.castError(err);
          const task = taskManagerSelectors.findTaskById(getState())(tasksIds[index]);

          if (task?.status !== TaskStatus.Cancelled) {
            dispatch(
              taskManagerActions.updateTask({
                taskId: taskId,
                merge: { status: TaskStatus.Error },
              }),
            );

            console.error(castedError);

            errors.push(castedError);
          }
        });
    }

    options.onSuccess?.();

    dispatch(planThunks.fetchUsageThunk());

    if (errors.length > 0) {
      for (const error of errors) {
        notificationsService.show(error.message, ToastType.Error);
      }

      throw new Error(i18n.get('error.uploadingItems'));
    }
  },
);

export const uploadItemsThunkExtraReducers = (builder: ActionReducerMapBuilder<StorageState>): void => {
  builder
    .addCase(uploadItemsThunk.pending, () => undefined)
    .addCase(uploadItemsThunk.fulfilled, () => undefined)
    .addCase(uploadItemsThunk.rejected, (state, action) => {
      const requestOptions = Object.assign(DEFAULT_OPTIONS, action.meta.arg.options || {});

      if (requestOptions?.showErrors) {
        notificationsService.show(
          i18n.get('error.uploadingFile', { reason: action.error.message || '' }),
          ToastType.Error,
        );
      }
    });
};
