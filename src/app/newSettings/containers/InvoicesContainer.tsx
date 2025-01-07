import { Invoice, UserType } from '@internxt/sdk/dist/drive/payments/types';
import { useTranslationContext } from '../../i18n/provider/TranslationProvider';
import { useEffect, useState } from 'react';
import Section from '../Sections/General/components/Section';
import paymentService from '../../payment/services/payment.service';
import Card from '../../shared/components/Card';
import InvoicesList from '../components/Invoices/InvoicesList';

const Invoices = ({ className = '', userType }: { className?: string; userType: UserType }): JSX.Element => {
  const { translate } = useTranslationContext();
  const [state, setState] = useState<{ tag: 'ready'; invoices: Invoice[] } | { tag: 'loading' | 'empty' }>({
    tag: 'loading',
  });
  const isEmpty = state.tag === 'empty';

  useEffect(() => {
    paymentService
      .getInvoices({ userType })
      .then((invoices) => setState({ tag: 'ready', invoices }))
      .catch(() => setState({ tag: 'empty' }));
  }, []);

  const invoices = state.tag === 'ready' ? state.invoices : [];

  return (
    <Section className={className} title={translate('views.account.tabs.billing.invoices.head')}>
      <Card className={`${isEmpty ? 'h-40' : 'pb-0'}`}>
        <InvoicesList invoices={invoices} state={state.tag} />
      </Card>
    </Section>
  );
};

export default Invoices;
