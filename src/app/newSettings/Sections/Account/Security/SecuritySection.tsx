import { UserSettings } from '@internxt/sdk/dist/shared/types/userSettings';
import { t } from 'i18next';
import { useState } from 'react';
import { useSelector } from 'react-redux';
import { RootState } from '../../../../store';
import { useAppDispatch } from '../../../../store/hooks';
import { refreshUserThunk } from '../../../../store/slices/user';
import Section from '../../General/components/Section';
import ChangePassword from './components/ChangePassword';
import EnterPassword from './components/EnterPassword';
import ExportBackupKey from './components/ExportBackupKey';
import FrecuentlyAskedQuestions from './components/FrecuentlyAskedQuestions';
import TwoFactorAuthentication from './components/TwoFactorAuthentication';

const SecuritySection = () => {
  const user = useSelector<RootState, UserSettings | undefined>((state) => state.user.user);
  const dispatch = useAppDispatch();

  const [state, setState] = useState<{ tag: 'locked' } | { tag: 'unlocked'; password: string }>({ tag: 'locked' });

  return (
    <Section
      title={t('preferences.account.security.title')}
      className="flex max-h-640 flex-1 flex-col space-y-6 overflow-y-auto p-6"
    >
      {state.tag === 'unlocked' ? (
        <>
          <div className="flex justify-between">
            <ChangePassword
              onPasswordChanged={(newPassword) => {
                setState({ tag: 'unlocked', password: newPassword });
                // timeout to prevent race condition
                setTimeout(() => dispatch(refreshUserThunk({ forceRefresh: true })), 4000);
              }}
              currentPassword={state.password}
              user={user}
            />
            <TwoFactorAuthentication password={state.password} />
          </div>
          <div className="flex justify-between">
            <ExportBackupKey />
          </div>
          <hr className="h-px border-gray-10" />
          <FrecuentlyAskedQuestions />
        </>
      ) : (
        <EnterPassword onUnlock={(password) => setState({ tag: 'unlocked', password })} user={user} />
      )}
    </Section>
  );
};

export default SecuritySection;
