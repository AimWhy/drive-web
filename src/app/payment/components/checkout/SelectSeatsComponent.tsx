import { useState } from 'react';
import Button from '../../../shared/components/Button/Button';
import { useTranslationContext } from 'app/i18n/provider/TranslationProvider';

interface SelectUsersComponentProps {
  disableMinusButton: boolean;
  disablePlusButton: boolean;
  maxSeats?: number;
  minSeats?: number;
  seats: number;
  onSeatsChange: (seats: number) => void;
}

const SeparatorVertical = () => <div className="h-max border-[0.5px] border-gray-10 py-1" />;

export const SelectSeatsComponent = ({
  disableMinusButton,
  disablePlusButton,
  maxSeats,
  minSeats,
  seats,
  onSeatsChange,
}: SelectUsersComponentProps): JSX.Element => {
  const { translate } = useTranslationContext();
  const [totalUsers, setTotalUsers] = useState<number>(seats);
  const [showApplyButton, setShowApplyButton] = useState<boolean>(false);

  const onSeatInputChange = () => {
    onSeatsChange(totalUsers);
    setShowApplyButton(false);
  };

  return (
    <div className="flex flex-row gap-4">
      <div
        role="menuitem"
        tabIndex={0}
        onKeyDown={(e) => {
          e.stopPropagation();
        }}
        className="flex w-max flex-row items-center rounded-lg border"
      >
        <button
          disabled={disableMinusButton}
          onClick={(e) => {
            e.preventDefault();
            onSeatsChange(seats - 1);
            setTotalUsers(seats - 1);
          }}
          className="flex h-full flex-col items-center justify-center rounded-l-lg px-4 hover:bg-gray-10"
        >
          -
        </button>
        <SeparatorVertical />
        <input
          type="text"
          className="flex w-16 items-center justify-center !rounded-none border-0 text-center !outline-none !ring-0"
          maxLength={3}
          value={totalUsers}
          onChange={(e) => {
            e.preventDefault();
            setTotalUsers(Number(e.target.value));
          }}
          onKeyDown={(e) => {
            e.stopPropagation();
            setShowApplyButton(true);
            if (e.key === 'Enter') {
              e.preventDefault();
              onSeatInputChange();
            }
          }}
        />
        <SeparatorVertical />
        <button
          disabled={disablePlusButton}
          onClick={(e) => {
            e.preventDefault();
            onSeatsChange(seats + 1);
            setTotalUsers(seats + 1);
          }}
          className="flex h-full flex-col items-center justify-center rounded-r-lg px-4 hover:bg-gray-10"
        >
          +
        </button>
      </div>
      {showApplyButton ? (
        <Button
          className="w-max"
          disabled={maxSeats && minSeats ? maxSeats < totalUsers || totalUsers < minSeats : undefined}
          type="button"
          variant="primary"
          onClick={onSeatInputChange}
        >
          <p>{translate('checkout.productCard.apply')}</p>
        </Button>
      ) : undefined}
    </div>
  );
};
