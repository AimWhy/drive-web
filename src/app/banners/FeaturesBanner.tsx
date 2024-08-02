import { CheckCircle, TreePalm, X } from '@phosphor-icons/react';

import { useTranslationContext } from 'app/i18n/provider/TranslationProvider';

const FeaturesBanner = ({ showBanner, onClose }: { showBanner: boolean; onClose: () => void }): JSX.Element => {
  const { translate, translateList } = useTranslationContext();

  const features = translateList('featuresBanner.features');

  const handleOnClick = () => {
    window.open('https://internxt.com/pricing', '_blank', 'noopener noreferrer');
    onClose();
  };

  return (
    //Background
    <div
      className={`${showBanner ? 'flex' : 'hidden'} fixed
         bottom-0 left-0 right-0 top-0 z-50 h-screen bg-black bg-opacity-50 px-10 lg:px-0`}
    >
      {/* Banner */}
      <div
        className={
          'fixed left-1/2 top-1/2 flex h-auto -translate-x-[50%] -translate-y-[50%] flex-col overflow-hidden rounded-[32px] border-4 border-primary/20 bg-white px-10'
        }
      >
        <button className="absolute  right-0 m-7 flex text-black hover:bg-white/5" onClick={onClose}>
          <X size={32} />
        </button>
        <div className="flex w-full flex-col space-x-10 py-14 lg:flex-row">
          <div className="flex  w-max max-w-[400px] flex-col  items-center justify-center space-y-3 text-center lg:items-start lg:justify-between lg:text-start">
            <div className="flex items-center gap-1 rounded-xl bg-primary/10 px-3 py-1.5 font-bold text-primary">
              {/* <p className="text-xs">{translate('featuresBanner.label.upTo')}</p> */}
              <p className="text-2xl">{translate('featuresBanner.label.discount')}</p>
            </div>
            <p className="w-full text-5xl font-bold leading-tight text-gray-80 dark:text-gray-20">
              {translate('featuresBanner.title')}
            </p>

            {/* <p className="w-full text-lg font-semibold text-gray-80 dark:text-gray-20">
              {translate('featuresBanner.subtitle.line1')}{' '}
              <span className="font-bold">
                {translate('featuresBanner.subtitle.line2.normal1')}
                <button onClick={handleCopyOnClipboardAction} className="cursor-pointer text-primary hover:underline">
                  {translate('featuresBanner.subtitle.line2.blue')}
                </button>
                {translate('featuresBanner.subtitle.line2.normal2')}
              </span>
            </p> */}

            <div className="flex flex-col items-center space-y-3 lg:items-start">
              <button
                onClick={handleOnClick}
                className="flex w-max items-center rounded-lg bg-primary px-5 py-3 text-lg font-medium text-white hover:bg-primary-dark"
              >
                {translate('featuresBanner.cta')}
              </button>
              <div className="flex flex-row space-x-3 pt-2 text-gray-80 dark:text-gray-20">
                <div className="flex h-6 w-6">
                  <CheckCircle size={24} className="mt-0.5 w-max text-primary" />
                </div>
                <p className="font-medium lg:text-lg">{translate('featuresBanner.guarantee')}</p>
              </div>

              {/* <p className="text-sm font-medium text-gray-50">{translate('featuresBanner.lastCta')}</p> */}
            </div>
          </div>
          <div className="hidden items-center lg:flex">
            <div className="flex flex-col">
              <div className="flex flex-col space-y-8">
                {features.map((card) => (
                  <div className="flex flex-row items-center space-x-4" key={card}>
                    <TreePalm weight="fill" size={32} className="text-primary" />
                    <p className="whitespace-nowrap text-xl font-semibold text-gray-80 dark:text-gray-20">{card}</p>
                  </div>
                ))}
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default FeaturesBanner;
