import React from 'react';
import { FileDown, FileJson } from 'lucide-react';

import Modal from '../ui/Modal';
import Button from '../ui/Button';
import AlertSheetView from './AlertSheetView';
import { exportPdf, exportStix21 } from '../../utils/export';

/**
 * AlertSheetModal — full-screen viewer for an Alert Sheet (the supervisor's
 * 4-point template) with one-click PDF and STIX 2.1 export.
 */
export default function AlertSheetModal({ sheet, onClose }) {
  if (!sheet) return null;
  return (
    <Modal
      open={!!sheet}
      onClose={onClose}
      title={`Alert Sheet — ${sheet.vuln_cve}`}
      subtitle={`Risk ${sheet.risk_level_label} · threat score ${sheet.threat_score}`}
      width="max-w-5xl"
      footer={
        <>
          <Button variant="secondary" icon={FileDown} onClick={() => exportPdf(sheet)}>
            Export as PDF
          </Button>
          <Button variant="secondary" icon={FileJson} onClick={() => exportStix21(sheet)}>
            Export to MISP / STIX 2.1
          </Button>
          <Button variant="primary" onClick={onClose}>
            Close
          </Button>
        </>
      }
    >
      <AlertSheetView sheet={sheet} />
    </Modal>
  );
}
