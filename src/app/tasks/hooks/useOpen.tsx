import { useCallback } from 'react';
import navigationService from '../../core/services/navigation.service';
import { TaskNotification, TaskType } from '../types';

interface OpenItem {
  openItem: () => void;
}

export const useOpenItem = (notification: TaskNotification): OpenItem => {
  const openItem = useCallback(() => {
    const { item, action } = notification;
    const isFolderUpload = action === TaskType.UploadFolder;

    if (isFolderUpload) {
      const folder = notification?.folderToUpload?.folder;
      const currentFolderId = notification?.folderToUpload?.parentFolderId;
      if (folder && currentFolderId) {
        navigationService.pushFolder(notification?.itemUUID?.rootFolderUUID);
      }
    } else if (item) {
      navigationService.pushFile(notification?.itemUUID?.fileUUID);
    }
  }, [notification]);

  return { openItem };
};
