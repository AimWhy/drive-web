import React from 'react'
import { Button } from 'react-bootstrap'

const AppSumoTiers = [
  { name: 'internxt_free1', size: '2GB' },
  { name: 'internxt_tier1', size: '500GB' },
  { name: 'internxt_tier2', size: '1TB' },
  { name: 'internxt_tier3', size: '2TB' },
  { name: 'internxt_tier4', size: '3TB' },
  { name: 'internxt_tier5', size: '5TB' }
];


interface AppSumoPlansProps {
  details?: any
}

function getAppSumoSize(name: string) {
  if (!name) {
    return 'undefined'
  }
  const find = AppSumoTiers.find(x => x.name === name)

  if (find) {
    return find.name + ' ' + find.size;
  } else {
    return name;
  }
}

export default function AppSumoPlans(props: AppSumoPlansProps) {
  return <div>
    <p className="title1">AppSumo license <span style={{ fontWeight: 'normal', color: '#7e848c' }}>| {getAppSumoSize(props.details.planId)}</span></p>
    <div style={{ textAlign: 'center' }}>
      <Button
        type="submit"
        size="sm"
        onClick={() => {
          window.open(`https://appsumo.com/account/redemption/${props.details.invoiceItemUuid}`, '_blank');
        }}
        style={{
          width: '28%',
          height: '40px',
          background: 'linear-gradient(74deg, #096dff, #00b1ff)',
          borderWidth: '0px'
        }}>Change plan</Button>
    </div>
  </div>;
}