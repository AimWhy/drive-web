import { useTranslationContext } from 'app/i18n/provider/TranslationProvider';
import Section from '../../../../newSettings/components/Section';
import { useState } from 'react';
import { ScrollableTable } from 'app/shared/tables/ScrollableTable';
import 'react-calendar/dist/Calendar.css';
import { TableCell, TableRow } from '@internxt/ui';
import { AccessLogsFilterOptions } from './components/AccessLogsFilterOptions';
import { useAccessLogs } from './hooks/useAccessLogs';
import { WorkspaceLogPlatform, WorkspaceLogType } from '@internxt/sdk/dist/workspaces';
import dateService from 'app/core/services/date.service';
import { useDebounce } from 'hooks/useDebounce';
import { ArrowDown, ArrowUp } from '@phosphor-icons/react';
import { getEnumKey } from '../../../utils/LogsUtils';

interface LogsViewProps {
  onClosePreferences: () => void;
}

interface HeaderItemsProps {
  title: string;
  isSortByAvailable: boolean;
  sortKey?: 'updatedAt' | 'platform' | 'type';
  defaultSort?: 'ASC' | 'DESC';
}

export const AccessLogsSection = ({ onClosePreferences }: LogsViewProps): JSX.Element => {
  const { translate } = useTranslationContext();
  const [searchMembersInputValue, setSearchMembersInputValue] = useState<string>('');
  const [daysFilter, setDaysFilter] = useState<number | undefined>();
  const [activityFilter, setActivityFilter] = useState<WorkspaceLogType[]>([]);
  const [orderBy, setOrderBy] = useState<{ key: 'updatedAt' | 'type' | 'platform'; direction: 'ASC' | 'DESC' }>({
    key: 'updatedAt',
    direction: 'DESC',
  });
  const debouncedSearchMemberValue = useDebounce(searchMembersInputValue, 500);
  const { accessLogs, isLoading, hasMoreItems, loadMoreItems } = useAccessLogs({
    activity: activityFilter,
    lastDays: daysFilter,
    member: debouncedSearchMemberValue,
    orderBy: [orderBy.key, orderBy.direction].join(':'),
  });

  function getActivityType(type: WorkspaceLogType) {
    const getLogKey = getEnumKey(WorkspaceLogType, type);
    return translate(`preferences.workspace.accessLogs.filterActions.activity.${getLogKey}`) || 'Unknown action';
  }

  function getPlatformType(platform: WorkspaceLogPlatform) {
    const getPlatformKey = getEnumKey(WorkspaceLogPlatform, platform);
    return translate(`preferences.workspace.accessLogs.filterActions.platform.${getPlatformKey}`) || 'Unknown';
  }

  const handleActivityFilters = (actionType: WorkspaceLogType) => {
    const isFilterActivated = activityFilter?.some((activity) => activity === actionType);
    const newActivityFilters = isFilterActivated
      ? activityFilter.filter((activity) => activity !== actionType)
      : [...activityFilter, actionType];

    setActivityFilter(newActivityFilters);
  };

  const handleDaysFilter = (days: number) => {
    setDaysFilter(days);
  };

  const onClearAllFilters = () => {
    setSearchMembersInputValue('');
    setDaysFilter(undefined);
    setActivityFilter([]);
    setOrderBy({
      key: 'updatedAt',
      direction: 'DESC',
    });
  };

  const formatDate = (updatedAt: Date) => {
    const formatted = dateService.format(updatedAt, 'MMM D, YYYY');
    return formatted.charAt(0).toUpperCase() + formatted.slice(1);
  };

  const formatTime = (updatedAt: Date) => dateService.format(updatedAt, 'hh:mm A');

  const headerList: HeaderItemsProps[] = [
    {
      title: translate('preferences.workspace.accessLogs.headerTable.date'),
      isSortByAvailable: true,
      sortKey: 'updatedAt',
      defaultSort: 'ASC',
    },
    {
      title: translate('preferences.workspace.accessLogs.headerTable.member'),
      isSortByAvailable: false,
    },
    {
      title: translate('preferences.workspace.accessLogs.headerTable.activity'),
      isSortByAvailable: true,
      sortKey: 'type',
      defaultSort: 'ASC',
    },
    {
      title: translate('preferences.workspace.accessLogs.headerTable.access'),
      isSortByAvailable: true,
      sortKey: 'platform',
      defaultSort: 'ASC',
    },
  ];

  const onSortByChange = (item: HeaderItemsProps) => {
    if (!item.isSortByAvailable) return;

    const newSortBy = {
      key: item.sortKey,
      direction: orderBy.key === item.sortKey ? (orderBy.direction === 'ASC' ? 'DESC' : 'ASC') : item.defaultSort,
    };

    setOrderBy(newSortBy as any);
  };

  const renderHeader = () => (
    <TableRow>
      {headerList.map((header, index) => (
        <TableCell
          key={header.title}
          onClick={() => header.isSortByAvailable && onSortByChange(header)}
          isHeader
          className={`py-3 text-left font-medium ${header.isSortByAvailable && 'cursor-pointer'}`}
        >
          <div className="flex h-full flex-row justify-between pl-4">
            <div className="flex w-full flex-row items-center gap-2">
              {header.title}
              {header.isSortByAvailable &&
                orderBy.key === header.sortKey &&
                (orderBy?.direction === 'ASC' ? (
                  <ArrowUp size={12} weight="bold" />
                ) : (
                  <ArrowDown size={12} weight="bold" />
                ))}
            </div>
            {index === headerList.length - 1 ? undefined : <div className="border border-gray-10" />}
          </div>
        </TableCell>
      ))}
    </TableRow>
  );

  const renderBody = () => {
    return accessLogs.map((item) => {
      const userEmail = item.user.email;
      const userName = item.user.name + ' ' + (item.user.lastname ?? null);
      const itemName = item.file?.plainName ?? item.folder?.plainName ?? 'Unknown';
      return (
        <TableRow key={item.id} className="border-b border-gray-10 text-sm last:border-none hover:bg-gray-5">
          <TableCell
            style={{
              width: '30%',
            }}
            className="py-2 pl-4"
          >
            <div className="flex flex-col gap-1">
              <p className="font-medium text-gray-100">{formatDate(item.updatedAt)}</p>
              <p className="text-gray-50">{formatTime(item.updatedAt)}</p>
            </div>
          </TableCell>
          <TableCell
            style={{
              width: '30%',
            }}
            className="py-2 pl-4"
          >
            <div className="flex w-screen max-w-[150px] flex-col gap-1 truncate">
              <p className={'font-medium'}>{userName}</p>
              <p title={userEmail} className="truncate text-gray-50">
                {userEmail}
              </p>
            </div>
          </TableCell>
          <TableCell
            style={{
              width: '20%',
            }}
            className="py-2 pl-4"
          >
            <div className="flex w-screen max-w-[150px] flex-col gap-1 truncate">
              <p className={'font-medium'}>{getActivityType(item.type)}</p>
              <p title={itemName} className="truncate text-gray-50">
                {itemName}
              </p>
            </div>
          </TableCell>
          <TableCell
            style={{
              width: '20%',
            }}
            className="py-2 pl-4"
          >
            {getPlatformType(item.platform)}
          </TableCell>
        </TableRow>
      );
    });
  };

  return (
    <Section title={translate('preferences.navBarSections.logs')} onClosePreferences={onClosePreferences}>
      <div className="flex h-screen w-full flex-col gap-6 overflow-hidden">
        <AccessLogsFilterOptions
          searchMembersInputValue={searchMembersInputValue}
          selectedFilters={{
            activity: activityFilter,
            days: daysFilter,
          }}
          handleDaysFilter={handleDaysFilter}
          onClearAllFilters={onClearAllFilters}
          onChangeActivityFilters={handleActivityFilters}
          onSearchMembersInputValueChange={setSearchMembersInputValue}
          translate={translate}
        />
        {accessLogs.length > 0 ? (
          <ScrollableTable
            tableHeaderClassName="sticky top-0 z-10 border-b border-gray-10 bg-gray-5 font-semibold text-gray-100"
            tableClassName="min-w-full rounded-lg border border-gray-10"
            tableBodyClassName="bg-surface dark:bg-gray-1"
            renderHeader={renderHeader}
            renderBody={renderBody}
            numOfColumnsForSkeleton={headerList.length ?? 4}
            scrollable
            loadMoreItems={loadMoreItems}
            hasMoreItems={hasMoreItems}
            isLoading={isLoading}
          />
        ) : (
          <div className="flex h-full w-full flex-col items-center justify-center">
            <p>There are not results</p>
          </div>
        )}
      </div>
    </Section>
  );
};
