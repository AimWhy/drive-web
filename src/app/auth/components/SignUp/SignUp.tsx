import { useState, useEffect, useMemo } from 'react';
import { SubmitHandler, useForm, useWatch } from 'react-hook-form';
import queryString from 'query-string';
import { auth } from '@internxt/lib';
import { Link } from 'react-router-dom';
import { Info, WarningCircle } from '@phosphor-icons/react';
import { Helmet } from 'react-helmet-async';
import localStorageService, { STORAGE_KEYS } from '../../../core/services/local-storage.service';

import { useAppDispatch } from '../../../store/hooks';
import { userActions, userThunks } from '../../../store/slices/user';
import { planThunks } from '../../../store/slices/plan';
import errorService from '../../../core/services/error.service';
import navigationService from '../../../core/services/navigation.service';
import { productsThunks } from '../../../store/slices/products';
import { AppView, IFormValues } from '../../../core/types';
import { referralsThunks } from '../../../store/slices/referrals';
import TextInput from '../TextInput/TextInput';
import PasswordInput from '../PasswordInput/PasswordInput';
import testPasswordStrength from '@internxt/lib/dist/src/auth/testPasswordStrength';
import PasswordStrengthIndicator from '../../../shared/components/PasswordStrengthIndicator';
import { useSignUp } from './useSignUp';
import { UserSettings } from '@internxt/sdk/dist/shared/types/userSettings';
import { useTranslationContext } from '../../../i18n/provider/TranslationProvider';
import authService, { getNewToken } from '../../../auth/services/auth.service';
import PreparingWorkspaceAnimation from '../PreparingWorkspaceAnimation/PreparingWorkspaceAnimation';
import paymentService from '../../../payment/services/payment.service';
import { MAX_PASSWORD_LENGTH } from '../../../shared/components/ValidPassword';
import { decryptPrivateKey } from '../../../crypto/services/keys.service';
import analyticsService from '../../../analytics/services/analytics.service';
import Button from '../../../shared/components/Button/Button';

export interface SignUpProps {
  location: {
    search: string;
  };
  isNewUser: boolean;
}

export type Views = 'signUp' | 'downloadBackupKey';

function SignUp(props: SignUpProps): JSX.Element {
  const { translate } = useTranslationContext();
  const [isValidPassword, setIsValidPassword] = useState(false);
  const [view, setView] = useState<Views>('signUp');

  const qs = queryString.parse(navigationService.history.location.search);
  const autoSubmit = useMemo(
    () => authService.extractOneUseCredentialsForAutoSubmit(new URLSearchParams(window.location.search)),
    [],
  );
  const hasReferrer = !!qs.ref;
  const { updateInfo, doRegister } = useSignUp(
    qs.register === 'activate' ? 'activate' : 'appsumo',
    hasReferrer ? String(qs.ref) : undefined,
  );
  const hasEmailParam = (qs.email && auth.isValidEmail(qs.email as string)) || false;

  const getInitialEmailValue = () => {
    if (hasEmailParam) {
      return qs.email as string;
    }

    if (autoSubmit.enabled && autoSubmit.credentials?.email) {
      return autoSubmit.credentials.email;
    }
  };
  const {
    register,
    formState: { errors, isValid },
    handleSubmit,
    control,
    getValues,
  } = useForm<IFormValues>({
    mode: 'onChange',
    defaultValues: {
      email: getInitialEmailValue(),
      password: autoSubmit.enabled && autoSubmit.credentials ? autoSubmit.credentials.password : '',
    },
  });
  const dispatch = useAppDispatch();
  const password = useWatch({ control, name: 'password', defaultValue: '' });
  const [signupError, setSignupError] = useState<Error | string>();
  const [showError, setShowError] = useState(false);
  const [isLoading, setIsLoading] = useState(false);
  const [passwordState, setPasswordState] = useState<{
    tag: 'error' | 'warning' | 'success';
    label: string;
  } | null>(null);
  const [showPasswordIndicator, setShowPasswordIndicator] = useState(false);
  const showPreparingWorkspaceAnimation = useMemo(() => autoSubmit.enabled && !showError, [autoSubmit, showError]);

  const formInputError = Object.values(errors)[0];

  let bottomInfoError: null | string = null;

  if (formInputError?.message) {
    bottomInfoError = formInputError.message;
  } else if (showError && signupError) {
    bottomInfoError = signupError.toString();
  }

  useEffect(() => {
    if (autoSubmit.enabled && autoSubmit.credentials) {
      onSubmit(getValues());
    }
  }, []);

  useEffect(() => {
    if (password.length > 0) onChangeHandler(password);
  }, [password]);

  function onChangeHandler(input: string) {
    setIsValidPassword(false);
    if (input.length > MAX_PASSWORD_LENGTH) {
      setPasswordState({ tag: 'error', label: translate('modals.changePasswordModal.errors.longPassword') });
      return;
    }

    const result = testPasswordStrength(input, (qs.email as string) === undefined ? '' : (qs.email as string));

    setIsValidPassword(result.valid);
    if (!result.valid) {
      setPasswordState({
        tag: 'error',
        label:
          result.reason === 'NOT_COMPLEX_ENOUGH'
            ? 'Password is not complex enough'
            : 'Password has to be at least 8 characters long',
      });
    } else if (result.strength === 'medium') {
      setPasswordState({ tag: 'warning', label: 'Password is weak' });
    } else {
      setPasswordState({ tag: 'success', label: 'Password is strong' });
    }
  }

  const onSubmit: SubmitHandler<IFormValues> = async (formData, event) => {
    const redeemCodeObject = autoSubmit.credentials && autoSubmit.credentials.redeemCodeObject;
    event?.preventDefault();
    setIsLoading(true);

    try {
      const { isNewUser } = props;
      const { email, password, token } = formData;
      const { xUser, xToken, mnemonic } = isNewUser
        ? await doRegister(email, password, token)
        : await updateInfo(email, password);

      localStorageService.clear();

      localStorageService.set('xToken', xToken);
      localStorageService.set('xMnemonic', mnemonic);

      const xNewToken = await getNewToken();
      localStorageService.set('xNewToken', xNewToken);

      const privateKey = xUser.privateKey
        ? Buffer.from(await decryptPrivateKey(xUser.privateKey, password)).toString('base64')
        : undefined;

      const user = {
        ...xUser,
        privateKey,
      } as UserSettings;

      dispatch(userActions.setUser(user));
      await dispatch(userThunks.initializeUserThunk());
      dispatch(productsThunks.initializeThunk());
      dispatch(planThunks.initializeThunk());

      if (isNewUser) {
        dispatch(referralsThunks.initializeThunk());
      }

      await analyticsService.trackSignUp(xUser.uuid, email);

      const urlParams = new URLSearchParams(window.location.search);
      const isUniversalLinkMode = urlParams.get('universalLink') == 'true';

      const redirectUrl = authService.getRedirectUrl(urlParams, xToken);

      if (redirectUrl) {
        window.location.replace(redirectUrl);
        return;
      } else if (redeemCodeObject) {
        await paymentService.redeemCode(redeemCodeObject).catch((err) => {
          errorService.reportError(err);
        });
        dispatch(planThunks.initializeThunk());
        navigationService.push(AppView.Drive);
      } else {
        if (isUniversalLinkMode) {
          return navigationService.push(AppView.UniversalLinkSuccess);
        } else {
          //TODO: Use this setState when we have to implement the download of the backup key
          // setView('downloadBackupKey');
          return navigationService.push(AppView.Drive);
        }
      }
    } catch (err: unknown) {
      setIsLoading(false);
      errorService.reportError(err);
      const castedError = errorService.castError(err);
      setSignupError(castedError.message);
    } finally {
      setShowError(true);
    }
  };

  const getLoginLink = () => {
    const currentParams = new URLSearchParams(window.location.search);

    return currentParams.toString() ? '/login?' + currentParams.toString() : '/login';
  };

  return (
    <>
      <Helmet>
        <link rel="canonical" href={`${process.env.REACT_APP_HOSTNAME}/new`} />
      </Helmet>
      <div
        className={`flex ${
          showPreparingWorkspaceAnimation
            ? 'h-full w-full'
            : 'h-fit w-96 flex-col items-center justify-center px-8 py-10'
        }`}
      >
        {showPreparingWorkspaceAnimation ? (
          <PreparingWorkspaceAnimation />
        ) : view === 'downloadBackupKey' ? (
          //TODO: Use this component when we have to implement the download of the backup key
          // <DownloadBackupKey onRedirect={onRedirect} />
          <></>
        ) : (
          <div className="flex flex-col items-start space-y-5">
            <div className="flex flex-col items-start space-y-5">
              <h1 className="text-3xl font-medium">{translate('auth.signup.title')}</h1>

              <form className="flex w-full flex-col space-y-2" onSubmit={handleSubmit(onSubmit)}>
                <TextInput
                  placeholder={translate('auth.email') as string}
                  label="email"
                  type="email"
                  disabled={hasEmailParam}
                  register={register}
                  required={true}
                  minLength={{ value: 1, message: 'Email must not be empty' }}
                  error={errors.email}
                />

                <label className="space-y-0.5">
                  <PasswordInput
                    className={passwordState ? passwordState.tag : ''}
                    placeholder={translate('auth.password')}
                    label="password"
                    maxLength={MAX_PASSWORD_LENGTH}
                    register={register}
                    onFocus={() => setShowPasswordIndicator(true)}
                    required={true}
                    error={errors.password}
                  />
                  {showPasswordIndicator && passwordState && (
                    <PasswordStrengthIndicator
                      className="pt-1"
                      strength={passwordState.tag}
                      label={passwordState.label}
                    />
                  )}
                  {bottomInfoError && (
                    <div className="flex flex-row items-start pt-1">
                      <div className="flex h-5 flex-row items-center">
                        <WarningCircle weight="fill" className="mr-1 h-4 text-red" />
                      </div>
                      <span className="font-base w-56 text-sm text-red">{bottomInfoError}</span>
                    </div>
                  )}
                </label>

                <div className="flex space-x-2.5 rounded-lg bg-primary/10 p-3 pr-4 dark:bg-primary/20">
                  <Info size={20} className="shrink-0 text-primary" />
                  <p className="text-xs">
                    {translate('auth.signup.info.normalText')}{' '}
                    <span className="font-semibold">{translate('auth.signup.info.boldText')}</span>{' '}
                    <span className="font-semibold text-primary underline">
                      <a
                        href="https://help.internxt.com/en/articles/8450457-how-do-i-create-a-backup-key"
                        target="_blank"
                      >
                        {translate('auth.signup.info.cta')}
                      </a>
                    </span>
                  </p>
                </div>

                <Button
                  disabled={isLoading || !isValidPassword}
                  loading={isLoading}
                  type="submit"
                  variant="primary"
                  className="w-full"
                >
                  {isLoading && isValid && isValidPassword
                    ? `${translate('auth.signup.encrypting')}...`
                    : translate('auth.signup.title')}
                </Button>
              </form>

              <span className="mt-2 w-full text-xs text-gray-50">
                {translate('auth.terms1')}{' '}
                <a
                  href="https://internxt.com/legal"
                  target="_blank"
                  className="text-xs text-gray-50 hover:text-gray-60"
                >
                  {translate('auth.terms2')}
                </a>
              </span>

              <div className="w-full border-b border-gray-10" />

              <div className="flex w-full items-center justify-center space-x-1.5 font-medium">
                <span>{translate('auth.signup.haveAccount')}</span>
                <Link
                  to={getLoginLink()}
                  className="cursor-pointer font-medium text-primary no-underline hover:text-primary focus:text-primary-dark"
                >
                  {translate('auth.signup.login')}
                </Link>
              </div>
            </div>
          </div>
        )}
      </div>
    </>
  );
}

export default SignUp;
