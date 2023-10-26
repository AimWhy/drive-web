import { PencilSimple, Trash, DownloadSimple, Link, Users, Eye } from '@phosphor-icons/react';
import { DriveItemAction } from '../DriveExplorer/DriveExplorerItem';
import { useTranslationContext } from 'app/i18n/provider/TranslationProvider';
import { useAppDispatch } from 'app/store/hooks';
import { uiActions } from 'app/store/slices/ui';
import { Menu } from '@headlessui/react';
import { storageActions } from 'app/store/slices/storage';
import { DriveItemData } from 'app/drive/types';
import shareService from 'app/share/services/share.service';
import storageThunks from 'app/store/slices/storage/storage.thunks';
import moveItemsToTrash from 'use_cases/trash/move-items-to-trash';

interface FileDropdownActionsProps {
  title?: string;
  hiddenActions: DriveItemAction[];
  onRenameButtonClicked: any;
  isTrash?: boolean;
  item?: DriveItemData;
  closeDropdown: () => void;
  openDropdown: boolean;
}

type MenuItem =
  | {
      icon: any;
      text: string;
      onClick: () => void;
      className?: string;
      iconClassName?: string;
    }
  | {
      divider: boolean;
    }
  | null;

const FileDropdownActions = (props: FileDropdownActionsProps) => {
  const dispatch = useAppDispatch();
  const { translate } = useTranslationContext();

  const { title } = props;

  const menuItems: MenuItem[] = [
    {
      icon: Users,
      text: translate('drive.dropdown.share'),

      onClick: () => {
        dispatch(
          storageActions.setItemToShare({
            share: (props.item as DriveItemData)?.shares?.[0],
            item: props.item as DriveItemData,
          }),
        );
        dispatch(uiActions.setIsShareDialogOpen(true));
      },
    },
    {
      icon: Link,
      text: translate('drive.dropdown.getLink'),

      onClick: () => {
        const driveItem = props.item as DriveItemData;
        shareService.getPublicShareLink(driveItem.uuid as string, driveItem.isFolder ? 'folder' : 'file');
      },
    },
    { divider: true },
    !props.item?.isFolder
      ? {
          icon: Eye,
          text: translate('drive.dropdown.openPreview'),

          onClick: () => {
            dispatch(uiActions.setIsFileViewerOpen(true));
            dispatch(uiActions.setFileViewerItem(props.item as DriveItemData));
          },
        }
      : null,
    {
      icon: PencilSimple,
      text: translate('drive.dropdown.rename'),

      onClick: () => props.onRenameButtonClicked(props.item as DriveItemData),
    },
    // {
    //   icon: ArrowsOutCardinal,
    //   text: translate('drive.dropdown.move'),

    //   onClick: () => {
    //     dispatch(storageActions.setItemsToMove([props.item as DriveItemData]));
    //     dispatch(uiActions.setIsMoveItemsDialogOpen(true));
    //   },
    // },
    {
      icon: DownloadSimple,
      text: translate('drive.dropdown.download'),

      onClick: () => {
        dispatch(storageThunks.downloadItemsThunk([props.item as DriveItemData]));
      },
    },
    { divider: true },
    {
      icon: Trash,
      text: props.isTrash ? translate('drive.dropdown.deletePermanently') : translate('drive.dropdown.moveToTrash'),
      className: !props.isTrash ? 'text-red-60 hover:text-red-60' : '',
      iconClassName: props.isTrash ? 'text-blue-60' : '',

      onClick: () => {
        moveItemsToTrash([props.item as DriveItemData]);
      },
    },
  ];

  // Ahora, 'menuItems' contiene divisores dentro del arreglo que se usarán en la representación del menú.

  return (
    <div className="absolute z-20 mt-0 flex flex-col rounded-lg bg-white py-1.5 shadow-subtle-hard outline-none">
      {title ? <span className="mb-1 text-supporting-2">{title}</span> : null}
      {props.openDropdown && (
        <>
          {menuItems.map((item, index) => (
            <div key={`dropdown-item-${index}`}>
              {item && 'divider' in item ? (
                <div className="my-0.5 flex w-full flex-row px-4">
                  <div className="h-px w-full bg-gray-10" />
                </div>
              ) : (
                item && (
                  <Menu.Item as={'div'}>
                    <div
                      onClick={(e) => {
                        e.stopPropagation();
                        e.preventDefault();
                        item.onClick();
                        props.closeDropdown();
                      }}
                      className={`flex cursor-pointer flex-row whitespace-nowrap px-4 py-1.5 text-base text-gray-80 hover:bg-gray-5 hover:text-gray-100 ${item.className}`}
                    >
                      <div className="flex flex-row items-center space-x-2">
                        {item.icon && <item.icon size={20} className={item.iconClassName} />}
                        <span>{item.text}</span>
                      </div>
                    </div>
                  </Menu.Item>
                )
              )}
            </div>
          ))}
        </>
      )}
    </div>
  );
};

export default FileDropdownActions;
