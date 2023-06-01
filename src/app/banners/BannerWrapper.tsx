import localStorageService, { STORAGE_KEYS } from 'app/core/services/local-storage.service';
import { RootState } from 'app/store';
import { useAppSelector } from 'app/store/hooks';
import { PlanState } from 'app/store/slices/plan';
import { userSelectors } from 'app/store/slices/user';
import { useEffect, useState } from 'react';
import { useSelector } from 'react-redux';
import SummerBanner from './SummerBanner';

const BannerWrapper = () => {
  const [showBanner, setShowBanner] = useState(false);
  const plan = useSelector<RootState, PlanState>((state) => state.plan);
  const isTutorialCompleted = localStorageService.get(STORAGE_KEYS.SIGN_UP_TUTORIAL_COMPLETED);
  const userPlan = plan.subscription?.type;
  const isNewAccount = useAppSelector(userSelectors.hasSignedToday);

  const onCloseBanner = () => {
    setShowBanner(false);
    localStorage.setItem('showSummerBanner', 'false');
  };

  function isBannerOpen() {
    if (isNewAccount) {
      if (userPlan === 'free' && isTutorialCompleted && !localStorageService.get('showSummerBanner')) {
        setShowBanner(true);
      }
    } else {
      if (userPlan === 'free' && !localStorageService.get('showSummerBanner')) {
        setShowBanner(true);
      }
    }
  }

  useEffect(() => {
    isBannerOpen();
  }, [isTutorialCompleted, localStorageService.get('showSummerBanner'), userPlan, isNewAccount]);
  return <SummerBanner showBanner={showBanner} onClose={onCloseBanner} />;
};

export default BannerWrapper;
