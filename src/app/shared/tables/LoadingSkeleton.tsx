import { TableCell, TableRow } from '@internxt/internxtui';

export const LoadingRowSkeleton = ({ numberOfColumns }: { numberOfColumns: number }) => {
  const totalRowsArray = new Array(10).fill(null);
  return (
    <>
      {totalRowsArray.map((_, rowIndex) => (
        <TableRow key={`skeleton-row-${rowIndex}`}>
          {new Array(numberOfColumns).fill(null).map((_, cellIndex) => (
            <TableCell key={`skeleton-cell-${rowIndex}-${cellIndex}`}>
              <div className="h-4 w-20 animate-pulse rounded bg-gray-80 dark:bg-gray-20" />
            </TableCell>
          ))}
        </TableRow>
      ))}
    </>
  );
};
