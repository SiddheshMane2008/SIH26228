// Demo scenarios exposed by the backend at /api/demo/run-scenario/{id}.
export interface ScenarioDef { id: number; label: string; code: string; brief: string; expect: string }

export const SCENARIOS: ScenarioDef[] = [
  { id: 1, code: 'S-01', label: 'Clean baseline', brief: 'Verified dataset and model with intact lineage. Establishes the reference passport.', expect: 'ACCEPT' },
  { id: 2, code: 'S-02', label: 'Poisoned ingestion', brief: 'Backdoor trigger patches injected into a fraction of training images.', expect: 'QUARANTINE' },
  { id: 3, code: 'S-03', label: 'Model substitution', brief: 'Model artefact digest no longer matches its registered fingerprint.', expect: 'QUARANTINE' },
  { id: 4, code: 'S-04', label: 'Inference tampering', brief: 'Output modification and broken signature in hash-linked provenance chain.', expect: 'QUARANTINE' },
  { id: 5, code: 'S-05', label: 'Covariate shift', brief: 'Field imagery drifts from training distribution (heavy environmental fog).', expect: 'REVIEW' },
]

export const scenarioById = (id: number) => SCENARIOS.find((s) => s.id === id)
