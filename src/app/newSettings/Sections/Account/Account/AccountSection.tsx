import { UserSettings } from '@internxt/sdk/dist/shared/types/userSettings';
import { t } from 'i18next';
import { useState } from 'react';
import { useSelector } from 'react-redux';

import { areCredentialsCorrect } from '../../../../auth/services/auth.service';
import userService from '../../../../auth/services/user.service';

import errorService from '../../../../core/services/error.service';
import Section from 'app/newSettings/components/Section';

import { useTranslationContext } from '../../../../i18n/provider/TranslationProvider';
import notificationsService, { ToastType } from '../../../../notifications/services/notifications.service';

import Button from '../../../../shared/components/Button/Button';

import { RootState } from '../../../../store';
import { useAppDispatch } from '../../../../store/hooks';
import { updateUserProfileThunk } from '../../../../store/slices/user';

import ClearTrashDialog from '../../../../drive/components/ClearTrashDialog/ClearTrashDialog';
import AccountDetailsModal from './components/AccountDetailsModal';
import ChangeEmailModal from './components/ChangeEmailModal';
import EmailVerificationMessageCard from './components/EmailMessageCard';
import AccountUsageContainer from './containers/AccountUsageContainer';
import DeleteAccountContainer from './containers/DeleteAccountContainer';
import InviteFriendSectionContainer from './containers/InviteFriendSectionContainer';
import InvitedFriendsContainer from './containers/InvitedFriendsContainer';
import UserHeaderContainer from './containers/UserHeaderContainer';

interface AccountSectionProps {
  changeSection: ({ section, subsection }) => void;
  onClosePreferences: () => void;
}

const AccountSection = ({ changeSection, onClosePreferences }: AccountSectionProps) => {
  const dispatch = useAppDispatch();
  const { translate } = useTranslationContext();
  const user = useSelector<RootState, UserSettings | undefined>((state) => state.user.user);

  const isFreeAccount = user?.hasReferralsProgram;
  if (!user) throw new Error('User is not defined');

  const [isDetailsModalOpen, setIsDetailsModalOpen] = useState(false);
  const [isEmailModalOpen, setIsEmailModalOpen] = useState(false);
  const [isSendingVerificationEmail, setIsSendingVerificationEmail] = useState(false);
  const [isInvitationsViewVisible, setIsInvitationsViewVisible] = useState(false);

  const onResendEmailVerification = async () => {
    setIsSendingVerificationEmail(true);
    await userService.sendVerificationEmail();
    notificationsService.show({ text: t('notificationMessages.verificationEmail'), type: ToastType.Success });
    setIsSendingVerificationEmail(false);
  };

  const changeUserEmail = async (newEmail) => {
    await userService.changeEmail(newEmail);
    notificationsService.show({
      text: translate('views.account.tabs.account.accountDetails.changeEmail.sucessSendingVerification', {
        email: newEmail,
      }),
      type: ToastType.Success,
    });
  };

  const onChangeEmailError = (error: unknown) => {
    notificationsService.show({
      text: translate('views.account.tabs.account.accountDetails.changeEmail.errorSendingVerification'),
      type: ToastType.Error,
    });
    errorService.reportError(error);
  };

  const updateUserProfile = async ({ name, lastname }: { name: string; lastname: string }) => {
    await dispatch(updateUserProfileThunk({ name, lastname })).unwrap();
    notificationsService.show({
      text: translate('views.account.tabs.account.accountDetails.editProfile.updatedProfile'),
      type: ToastType.Success,
    });
  };

  return (
    <Section
      onBackButtonClicked={isInvitationsViewVisible ? () => setIsInvitationsViewVisible(false) : undefined}
      title={
        isInvitationsViewVisible
          ? translate('preferences.account.invitedFriends')
          : translate('preferences.account.title')
      }
      onClosePreferences={onClosePreferences}
    >
      {isInvitationsViewVisible ? (
        <InvitedFriendsContainer />
      ) : (
        <>
          <EmailVerificationMessageCard
            isVerified={user.emailVerified}
            disableButton={isSendingVerificationEmail}
            onClickResendButton={onResendEmailVerification}
          />
          <UserHeaderContainer />
          <div className="flex justify-center">
            <Button variant="secondary" className="w-32" onClick={() => setIsDetailsModalOpen(true)}>
              <span>{t('views.preferences.workspace.overview.edit')}</span>
            </Button>
          </div>
          {isFreeAccount && (
            <InviteFriendSectionContainer onSeeInvitationsButtonClicked={() => setIsInvitationsViewVisible(true)} />
          )}
          <AccountUsageContainer changeSection={changeSection} />
          <div>
            <div className="h-px w-full bg-gray-10" />
          </div>
          <DeleteAccountContainer />
        </>
      )}
      <AccountDetailsModal
        isOpen={isDetailsModalOpen}
        onClose={() => setIsDetailsModalOpen(false)}
        openEditEmail={() => {
          setIsDetailsModalOpen(false);
          setIsEmailModalOpen(true);
        }}
        name={user.name}
        lastname={user.lastname}
        email={user.email}
        onUpdateUserProfileData={updateUserProfile}
        onErrorUpdatingUserProfileData={() =>
          notificationsService.show({
            text: translate('views.account.tabs.account.accountDetails.editProfile.errorUpdatingProfile'),
            type: ToastType.Error,
          })
        }
      />
      <ChangeEmailModal
        isOpen={isEmailModalOpen}
        onClose={() => setIsEmailModalOpen(false)}
        email={user.email}
        checkEmailCredentials={areCredentialsCorrect}
        changeEmail={changeUserEmail}
        onChangeEmailError={onChangeEmailError}
      />
      <ClearTrashDialog />
    </Section>
  );
};

export default AccountSection;
