import { useSelector } from 'react-redux';

import BaseDialog from '../../../core/components/dialogs/BaseDialog/BaseDialog';
import { useState } from 'react';
import BaseButton from '../../../core/components/Buttons/BaseButton';
import errorService from '../../../core/services/error.service';
import storageThunks from '../../../store/slices/storage/storage.thunks';
import { uiActions } from '../../../store/slices/ui';
import { setItemsToDelete } from '../../../store/slices/storage';
import { useAppDispatch, useAppSelector } from '../../../store/hooks';
import { RootState } from '../../../store';
import { DriveItemData } from '../../types';
import i18n from 'app/i18n/services/i18n.service';

import './DeleteItemsDialog.scss';

interface DeleteItemsDialogProps {
  onItemsDeleted?: () => void;
}

const DeleteItemsDialog = (props: DeleteItemsDialogProps): JSX.Element => {
  const itemsToDelete: DriveItemData[] = useSelector((state: RootState) => state.storage.itemsToDelete);
  const [isLoading, setIsLoading] = useState(false);
  const dispatch = useAppDispatch();
  const isOpen = useAppSelector((state: RootState) => state.ui.isDeleteItemsDialogOpen);

  const onClose = (): void => {
    dispatch(uiActions.setIsDeleteItemsDialogOpen(false));
    dispatch(setItemsToDelete([]));
  };

  const onAccept = async (): Promise<void> => {
    try {
      setIsLoading(true);
      if (itemsToDelete.length > 0) {
        await dispatch(storageThunks.deleteItemsThunk(itemsToDelete));
      }

      props.onItemsDeleted && props.onItemsDeleted();

      setIsLoading(false);
      onClose();
    } catch (err: unknown) {
      const castedError = errorService.castError(err);

      setIsLoading(false);

      console.log(castedError.message);
    }
  };

  return (
    <BaseDialog isOpen={isOpen} title="Delete items" onClose={onClose}>
      <span className="text-center block w-full text-base px-8 text-neutral-900 mt-2">
        {i18n.get('drive.deleteItems.advice')}
      </span>

      <div className="flex justify-center items-center bg-l-neutral-20 py-6 mt-6">
        <div className="flex w-64">
          <BaseButton onClick={() => onClose()} className="cancel w-full mr-2">
            {i18n.get('actions.cancel')}
          </BaseButton>
          <BaseButton className="primary w-11/12 ml-2" disabled={isLoading} onClick={() => onAccept()}>
            {isLoading ? 'Deleting...' : 'Delete'}
          </BaseButton>
        </div>
      </div>
    </BaseDialog>
  );
};

export default DeleteItemsDialog;
