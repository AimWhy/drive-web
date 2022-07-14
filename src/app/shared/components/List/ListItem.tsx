import { Menu } from '@headlessui/react';
import { Check, DotsThree } from 'phosphor-react';

interface ItemProps {
  item: Record<string, unknown>;
  itemComposition: Array<(props: Record<string, unknown>, active: boolean) => JSX.Element>;
  selected: boolean;
  columns: Array<string>;
  toggleSelectItem: () => void;
  selectItem: () => void;
  menu?: Array<{
    separator?: boolean;
    name?: string;
    icon?: any;
    action?: (props: any) => void;
    disabled?: (props: any, selected: any) => boolean;
  }>;
}

export default function ListItem({
  item,
  itemComposition,
  selected,
  columns,
  toggleSelectItem,
  selectItem,
  menu,
}: ItemProps): JSX.Element {
  return (
    <div
      onClick={toggleSelectItem}
      className={`group relative flex h-14 flex-row items-center pl-14 pr-5 ${
        selected ? 'bg-primary bg-opacity-10 text-primary' : 'hover:bg-gray-1'
      }`}
    >
      {/* SELECTION CHECKBOX */}
      <div
        className={`absolute left-5 my-auto flex h-4 w-4 cursor-pointer flex-col items-center justify-center rounded text-white ${
          selected ? 'bg-primary' : 'border-gray-20 group-hover:border'
        }`}
      >
        <Check size={14} weight="bold" />
      </div>

      {/* COLUMNS */}
      {new Array(itemComposition.length).fill(0).map((col, i) => (
        <div
          key={`${item}-${col}-${i}`}
          className={`relative flex h-full flex-shrink-0 flex-row items-center border-b ${
            selected ? 'border-primary border-opacity-5' : 'border-gray-5'
          } ${columns[i]}`}
        >
          {itemComposition[i](item, selected)}
        </div>
      ))}

      <div className="flex h-14 w-14 flex-shrink-0 flex-col items-center justify-center">
        <Menu as="div" className="relative" onMouseDown={selectItem}>
          <Menu.Button
            className={`flex h-10 w-10 flex-col items-center justify-center rounded-md opacity-0 group-hover:opacity-100 ${
              selected ? 'text-primary hover:bg-primary hover:bg-opacity-10' : 'text-gray-60 hover:bg-gray-10'
            }`}
          >
            <DotsThree size={24} weight="bold" />
          </Menu.Button>
          <Menu.Items>
            <div className="absolute right-0 z-20 mt-0 flex flex-col rounded-md border border-gray-5 bg-white py-1.5 shadow-subtle-hard">
              {menu?.map((option) => (
                <>
                  {option.separator ? (
                    <div className="my-0.5 flex w-full flex-row px-4">
                      <div className="h-px w-full bg-gray-10" />
                    </div>
                  ) : (
                    <Menu.Item disabled={option.disabled?.(item, selected)}>
                      {({ active }) => (
                        <div
                          onClick={() => option.action?.(item)}
                          className={`flex cursor-pointer flex-row whitespace-nowrap px-3 py-1.5 text-base ${
                            active
                              ? 'bg-primary text-white'
                              : option.disabled?.(item, selected)
                              ? 'text-gray-40'
                              : 'text-gray-60'
                          }`}
                        >
                          <div className="flex flex-row items-center space-x-2">
                            {option.icon && <option.icon size={20} />}
                            <span>{option.name}</span>
                          </div>
                        </div>
                      )}
                    </Menu.Item>
                  )}
                </>
              ))}
            </div>
          </Menu.Items>
        </Menu>
      </div>
    </div>
  );
}
