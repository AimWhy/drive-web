import { Menu, Transition } from '@headlessui/react';
import { ReactNode } from 'react';

export default function Dropdown({
  children,
  options,
  classButton,
  menuItems,
  classMenuItems,
  openDirection,
}: {
  children: ReactNode | ((obj: any) => JSX.Element);
  options?: { text: string; onClick: () => void }[];
  classButton?: string;
  menuItems?: ReactNode[];
  classMenuItems: string;
  openDirection: 'left' | 'right';
}): JSX.Element {
  return (
    <Menu as="div" className="relative outline-none">
      <Menu.Button className={`cursor-pointer outline-none ${classButton}`}>{children}</Menu.Button>

      <Transition
        className={`absolute ${openDirection === 'left' ? 'left-0' : 'right-0'}`}
        enter={`${openDirection === 'left' ? 'origin-top-left' : 'otigin-top-right'} transition duration-100 ease-out`}
        enterFrom="scale-95 opacity-0"
        enterTo="scale-100 opacity-100"
        leave={`${openDirection === 'left' ? 'origin-top-left' : 'otigin-top-right'} transition duration-100 ease-out`}
        leaveFrom="scale-95 opacity-100"
        leaveTo="scale-100 opacity-0"
      >
        <Menu.Items className={`absolute shadow-subtle-hard ${classMenuItems}`}>
          {options?.map((option) => (
            <Menu.Item key={option.text}>
              <div
                className="cursor-pointer px-3 py-1.5 text-gray-80 hover:bg-primary hover:text-white active:bg-primary-dark"
                onClick={option.onClick}
              >
                {option.text}
              </div>
            </Menu.Item>
          ))}
          {menuItems && (
            <div className="w-full max-w-xs">
              {menuItems?.map((item, index) => (
                <Menu.Item key={'menuitem-' + index}>{item}</Menu.Item>
              ))}
            </div>
          )}
        </Menu.Items>
      </Transition>
    </Menu>
  );
}
