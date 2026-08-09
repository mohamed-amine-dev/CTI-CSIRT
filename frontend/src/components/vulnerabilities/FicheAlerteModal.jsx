import React from 'react';
import { FileDown, FileJson } from 'lucide-react';

import Modal from '../ui/Modal';
import Button from '../ui/Button';
import FicheAlerteView from './FicheAlerteView';
import { exportPdf, exportStix21 } from '../../utils/export';

/**
 * FicheAlerteModal — full-screen viewer for a Fiche d'Alerte (the supervisor's
 * 4-point template) with one-click PDF and STIX 2.1 export.
 */
export default function FicheAlerteModal({ fiche, onClose }) {
  if (!fiche) return null;
  return (
    <Modal
      open={!!fiche}
      onClose={onClose}
      title={`Fiche d'Alerte — ${fiche.vuln_cve}`}
      subtitle={`Risk ${fiche.risk_level_label} · threat score ${fiche.threat_score}`}
      width="max-w-5xl"
      footer={
        <>
          <Button variant="secondary" icon={FileDown} onClick={() => exportPdf(fiche)}>
            Export as PDF
          </Button>
          <Button variant="secondary" icon={FileJson} onClick={() => exportStix21(fiche)}>
            Export to MISP / STIX 2.1
          </Button>
          <Button variant="primary" onClick={onClose}>
            Close
          </Button>
        </>
      }
    >
      <FicheAlerteView fiche={fiche} />
    </Modal>
  );
}
