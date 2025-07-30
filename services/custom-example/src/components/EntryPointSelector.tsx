import React from 'react';
import { config, ENTRYPOINT_VERSION_CONFIGS, type SupportedEntryPointVersion } from '../config';

interface EntryPointSelectorProps {
  selectedVersion: SupportedEntryPointVersion;
  onVersionChange: (version: SupportedEntryPointVersion) => void;
  disabled?: boolean;
}

export const EntryPointSelector: React.FC<EntryPointSelectorProps> = ({
  selectedVersion,
  onVersionChange,
  disabled = false,
}) => {
  return (
    <div style={{
      padding: '1rem',
      border: '2px solid #e5e7eb',
      borderRadius: '8px',
      marginBottom: '1rem',
      backgroundColor: '#f9fafb',
    }}>
      <h3 style={{ margin: '0 0 1rem 0', fontSize: '1.1rem', fontWeight: 'bold' }}>
        🔧 EntryPoint Version Configuration
      </h3>
      
      <div style={{ marginBottom: '0.5rem', fontSize: '0.9rem', color: '#6b7280' }}>
        Select the EntryPoint version to use for this session:
      </div>

      <div style={{ display: 'flex', gap: '1rem', flexWrap: 'wrap' }}>
        {(Object.entries(ENTRYPOINT_VERSION_CONFIGS) as [SupportedEntryPointVersion, typeof ENTRYPOINT_VERSION_CONFIGS[keyof typeof ENTRYPOINT_VERSION_CONFIGS]][]).map(([version, versionConfig]) => (
          <label
            key={version}
            style={{
              display: 'flex',
              alignItems: 'flex-start',
              gap: '0.5rem',
              padding: '0.75rem',
              border: selectedVersion === version ? '2px solid #3b82f6' : '1px solid #d1d5db',
              borderRadius: '6px',
              backgroundColor: selectedVersion === version ? '#eff6ff' : '#ffffff',
              cursor: disabled ? 'not-allowed' : 'pointer',
              opacity: disabled ? 0.6 : 1,
              minWidth: '200px',
            }}
          >
            <input
              type="radio"
              value={version}
              checked={selectedVersion === version}
              onChange={(e) => onVersionChange(e.target.value as SupportedEntryPointVersion)}
              disabled={disabled || !versionConfig.supported}
              style={{ marginTop: '0.1rem' }}
            />
            <div>
              <div style={{ fontWeight: 'bold', marginBottom: '0.25rem' }}>
                {versionConfig.name}
              </div>
              <div style={{ fontSize: '0.875rem', color: '#6b7280' }}>
                {versionConfig.description}
              </div>
              {!versionConfig.supported && (
                <div style={{ fontSize: '0.75rem', color: '#ef4444', marginTop: '0.25rem' }}>
                  Not yet supported
                </div>
              )}
            </div>
          </label>
        ))}
      </div>

      {selectedVersion && (
        <div style={{
          marginTop: '0.75rem',
          padding: '0.5rem',
          backgroundColor: '#f0f9ff',
          border: '1px solid #0284c7',
          borderRadius: '4px',
          fontSize: '0.875rem',
        }}>
          <strong>Selected:</strong> {ENTRYPOINT_VERSION_CONFIGS[selectedVersion].name}
          <br />
          <strong>Note:</strong> Changing the EntryPoint version will require reconnecting your wallet.
        </div>
      )}
    </div>
  );
}; 