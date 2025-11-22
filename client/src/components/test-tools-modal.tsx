import { memo } from "react";
import Calculator from "./calculator";
import PeriodicTable from "./periodic-table";

interface TestToolsModalProps {
  showCalculator: boolean;
  showPeriodicTable: boolean;
  onCloseCalculator: () => void;
  onClosePeriodicTable: () => void;
}

function TestToolsModal({
  showCalculator,
  showPeriodicTable,
  onCloseCalculator,
  onClosePeriodicTable,
}: TestToolsModalProps) {
  return (
    <>
      <Calculator 
        key="calculator-modal"
        isOpen={showCalculator}
        onClose={onCloseCalculator}
      />
      
      <PeriodicTable
        key="periodic-table-modal"
        isOpen={showPeriodicTable}
        onClose={onClosePeriodicTable}
      />
    </>
  );
}

export default memo(TestToolsModal);
