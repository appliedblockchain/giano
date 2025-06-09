import React, { useState, useEffect } from 'react';

type TransactionDetails = {
  to: string;
  data: string;
  value?: string;
  functionName?: string;
  args?: any[];
  description?: string;
};

type ReadOperation = {
  contract: string;
  functionName: string;
  description: string;
};

type ModalEvent =
  | { type: 'show_connection_modal' }
  | { type: 'show_loading'; message: string }
  | { type: 'show_error'; error: string }
  | { type: 'show_transaction_confirmation'; transaction: TransactionDetails }
  | { type: 'show_read_confirmation'; operation: ReadOperation }
  | { type: 'hide_modal' };

type GianoProvider = {
  onModalEvent: (listener: (event: ModalEvent) => void) => () => void;
  _handleConnectionChoice?: (choice: 'existing' | 'new') => void;
  _handleTransactionApproval?: (approved: boolean) => void;
  _handleReadApproval?: (approved: boolean) => void;
};

type Props = {
  provider: GianoProvider;
};

const GianoConnectionModal: React.FC<Props> = ({ provider }) => {
  const [isOpen, setIsOpen] = useState(false);
  const [step, setStep] = useState<'choice' | 'loading' | 'error' | 'transaction_confirmation' | 'read_confirmation'>('choice');
  const [message, setMessage] = useState('');
  const [error, setError] = useState('');
  const [transactionDetails, setTransactionDetails] = useState<TransactionDetails | null>(null);
  const [readOperation, setReadOperation] = useState<ReadOperation | null>(null);

  useEffect(() => {
    const unsubscribe = provider.onModalEvent((event) => {
      console.log('Modal received event:', event);
      switch (event.type) {
        case 'show_connection_modal':
          setIsOpen(true);
          setStep('choice');
          break;
        case 'show_loading':
          setIsOpen(true);
          setStep('loading');
          setMessage(event.message);
          break;
        case 'show_error':
          setIsOpen(true);
          setStep('error');
          setError(event.error);
          break;
        case 'show_transaction_confirmation':
          setIsOpen(true);
          setStep('transaction_confirmation');
          setTransactionDetails(event.transaction);
          break;
        case 'show_read_confirmation':
          setIsOpen(true);
          setStep('read_confirmation');
          setReadOperation(event.operation);
          break;
        case 'hide_modal':
          setIsOpen(false);
          setStep('choice');
          setMessage('');
          setError('');
          setTransactionDetails(null);
          setReadOperation(null);
          break;
      }
    });

    return unsubscribe;
  }, [provider]);

  const handleChoice = (choice: 'existing' | 'new') => {
    if (provider._handleConnectionChoice) {
      provider._handleConnectionChoice(choice);
    }
  };

  const handleTransactionApproval = (approved: boolean) => {
    if (provider._handleTransactionApproval) {
      provider._handleTransactionApproval(approved);
    }
  };

  const handleReadApproval = (approved: boolean) => {
    if (provider._handleReadApproval) {
      provider._handleReadApproval(approved);
    }
  };

  const handleClose = () => {
    // For confirmation steps, treat close as rejection
    if (step === 'transaction_confirmation') {
      handleTransactionApproval(false);
    } else if (step === 'read_confirmation') {
      handleReadApproval(false);
    } else {
      setIsOpen(false);
      setStep('choice');
      setMessage('');
      setError('');
    }
  };

  if (!isOpen) return null;

  return (
    <div className="modal-overlay">
      <div className="modal-content">
        <div className="modal-header">
          <h2>
            {step === 'choice' && 'Connect to Giano'}
            {step === 'loading' && 'Processing...'}
            {step === 'error' && 'Error'}
            {step === 'transaction_confirmation' && 'Confirm Transaction'}
            {step === 'read_confirmation' && 'Confirm Operation'}
          </h2>
          <button onClick={handleClose} className="close-button">
            ×
          </button>
        </div>

        {step === 'loading' && (
          <div className="loading-state">
            <div className="spinner" />
            <p>{message}</p>
          </div>
        )}

        {step === 'error' && (
          <div className="error-state">
            <div className="error-message">
              <p>{error}</p>
            </div>
            <button onClick={() => setStep('choice')} className="try-again-button">
              Try Again
            </button>
          </div>
        )}

        {step === 'transaction_confirmation' && transactionDetails && (
          <div className="confirmation-content">
            <div className="transaction-details">
              <h3>🔐 Sign Transaction</h3>
              <p className="description">{transactionDetails.description}</p>
              
              <div className="details-section">
                <div className="detail-row">
                  <span className="label">Function:</span>
                  <span className="value">{transactionDetails.functionName || 'Unknown'}</span>
                </div>
                {transactionDetails.args && (
                  <div className="detail-row">
                    <span className="label">Amount:</span>
                    <span className="value">{transactionDetails.args[0]}</span>
                  </div>
                )}
                <div className="detail-row">
                  <span className="label">To:</span>
                  <span className="value contract-address">
                    {transactionDetails.to.slice(0, 6)}...{transactionDetails.to.slice(-4)}
                  </span>
                </div>
              </div>
            </div>
            
            <div className="confirmation-buttons">
              <button 
                onClick={() => handleTransactionApproval(false)} 
                className="reject-button"
              >
                Reject
              </button>
              <button 
                onClick={() => handleTransactionApproval(true)} 
                className="approve-button"
              >
                Confirm
              </button>
            </div>
          </div>
        )}

        {step === 'read_confirmation' && readOperation && (
          <div className="confirmation-content">
            <div className="read-details">
              <h3>🔍 Confirm Operation</h3>
              <p className="description">{readOperation.description}</p>
              
              <div className="details-section">
                <div className="detail-row">
                  <span className="label">Function:</span>
                  <span className="value">{readOperation.functionName}</span>
                </div>
                <div className="detail-row">
                  <span className="label">Contract:</span>
                  <span className="value contract-address">
                    {readOperation.contract.slice(0, 6)}...{readOperation.contract.slice(-4)}
                  </span>
                </div>
              </div>
              
              <p className="auth-note">
                ℹ️ This operation requires authentication to verify your identity.
              </p>
            </div>
            
            <div className="confirmation-buttons">
              <button 
                onClick={() => handleReadApproval(false)} 
                className="reject-button"
              >
                Cancel
              </button>
              <button 
                onClick={() => handleReadApproval(true)} 
                className="approve-button"
              >
                Continue
              </button>
            </div>
          </div>
        )}

        {step === 'choice' && (
          <div className="choice-content">
            <div className="existing-passkeys">
              <h3>🔑 Use Existing Passkey</h3>
              <p className="use-description">
                Use a passkey that you&apos;ve already created for this site
              </p>
              <button
                onClick={() => handleChoice('existing')}
                className="use-existing-button"
              >
                🔑 Use Existing Passkey
              </button>
            </div>

            <div className="divider">or</div>

            <div className="create-new-section">
              <h3>➕ Create New Passkey</h3>
              <p className="create-description">
                Create a new passkey for secure, password-free authentication
              </p>
              <button
                onClick={() => handleChoice('new')}
                className="create-new-button"
              >
                ➕ Create New Passkey
              </button>
            </div>

            <div className="info-section">
              <h4>About Passkeys</h4>
              <ul>
                <li>• Secured by your device&apos;s biometrics or PIN</li>
                <li>• No passwords to remember or lose</li>
                <li>• Works across all your devices</li>
                <li>• Phishing-resistant and private</li>
              </ul>
            </div>
          </div>
        )}
      </div>

      <style jsx>{`
        .modal-overlay {
          position: fixed;
          top: 0;
          left: 0;
          right: 0;
          bottom: 0;
          background: rgba(0, 0, 0, 0.5);
          display: flex;
          align-items: center;
          justify-content: center;
          z-index: 1000;
        }

        .modal-content {
          background: white;
          border-radius: 12px;
          box-shadow: 0 20px 25px -5px rgba(0, 0, 0, 0.1);
          max-width: 400px;
          width: 90%;
          max-height: 90vh;
          overflow-y: auto;
          padding: 24px;
        }

        .modal-header {
          display: flex;
          justify-content: space-between;
          align-items: center;
          margin-bottom: 24px;
        }

        .modal-header h2 {
          margin: 0;
          font-size: 20px;
          font-weight: 600;
          color: #111827;
        }

        .close-button {
          background: none;
          border: none;
          font-size: 24px;
          cursor: pointer;
          color: #6b7280;
          width: 32px;
          height: 32px;
          display: flex;
          align-items: center;
          justify-content: center;
          border-radius: 6px;
        }

        .close-button:hover {
          background: #f3f4f6;
        }

        .choice-content {
          display: flex;
          flex-direction: column;
          gap: 24px;
        }

        .existing-passkeys h3,
        .create-new-section h3 {
          margin: 0 0 8px 0;
          font-size: 16px;
          font-weight: 600;
          color: #111827;
        }

        .use-description,
        .create-description {
          margin: 0 0 16px 0;
          color: #6b7280;
          font-size: 14px;
          line-height: 1.5;
        }

        .use-existing-button,
        .create-new-button {
          width: 100%;
          padding: 12px 16px;
          border: 2px solid #e5e7eb;
          border-radius: 8px;
          background: white;
          cursor: pointer;
          font-size: 14px;
          font-weight: 500;
          transition: all 0.2s;
          color: #374151;
        }

        .use-existing-button:hover {
          border-color: #3b82f6;
          background: #f8fafc;
        }

        .create-new-button {
          background: #3b82f6;
          border-color: #3b82f6;
          color: white;
        }

        .create-new-button:hover {
          background: #2563eb;
          border-color: #2563eb;
        }

        .divider {
          text-align: center;
          color: #9ca3af;
          font-size: 14px;
          position: relative;
        }

        .divider::before,
        .divider::after {
          content: '';
          position: absolute;
          top: 50%;
          width: 45%;
          height: 1px;
          background: #e5e7eb;
        }

        .divider::before {
          left: 0;
        }

        .divider::after {
          right: 0;
        }

        .info-section {
          background: #f9fafb;
          border-radius: 8px;
          padding: 16px;
        }

        .info-section h4 {
          margin: 0 0 12px 0;
          font-size: 14px;
          font-weight: 600;
          color: #374151;
        }

        .info-section ul {
          margin: 0;
          padding: 0;
          list-style: none;
        }

        .info-section li {
          color: #6b7280;
          font-size: 13px;
          line-height: 1.5;
          margin-bottom: 4px;
        }

        .loading-state {
          text-align: center;
          padding: 40px 20px;
        }

        .spinner {
          width: 40px;
          height: 40px;
          border: 3px solid #e5e7eb;
          border-top: 3px solid #3b82f6;
          border-radius: 50%;
          animation: spin 1s linear infinite;
          margin: 0 auto 16px;
        }

        @keyframes spin {
          0% { transform: rotate(0deg); }
          100% { transform: rotate(360deg); }
        }

        .loading-state p {
          margin: 0;
          color: #6b7280;
          font-size: 14px;
        }

        .error-state {
          text-align: center;
          padding: 20px;
        }

        .error-message {
          background: #fef2f2;
          border: 1px solid #fecaca;
          border-radius: 8px;
          padding: 16px;
          margin-bottom: 16px;
        }

        .error-message p {
          margin: 0;
          color: #dc2626;
          font-size: 14px;
        }

        .try-again-button {
          background: #3b82f6;
          color: white;
          border: none;
          border-radius: 6px;
          padding: 8px 16px;
          cursor: pointer;
          font-size: 14px;
          font-weight: 500;
        }

        .try-again-button:hover {
          background: #2563eb;
        }

        .confirmation-content {
          padding: 24px 0;
        }

        .transaction-details,
        .read-details {
          text-align: left;
          margin-bottom: 24px;
        }

        .transaction-details h3,
        .read-details h3 {
          margin: 0 0 16px 0;
          font-size: 18px;
          font-weight: 600;
          color: #111827;
          text-align: center;
        }

        .description {
          background: #f8fafc;
          border: 1px solid #e2e8f0;
          border-radius: 8px;
          padding: 12px;
          margin: 0 0 20px 0;
          color: #374151;
          font-size: 14px;
          font-weight: 500;
        }

        .details-section {
          background: #fafbfc;
          border-radius: 8px;
          padding: 16px;
          margin-bottom: 20px;
        }

        .detail-row {
          display: flex;
          justify-content: space-between;
          align-items: center;
          margin-bottom: 12px;
        }

        .detail-row:last-child {
          margin-bottom: 0;
        }

        .label {
          font-weight: 600;
          color: #6b7280;
          font-size: 13px;
        }

        .value {
          color: #111827;
          font-weight: 500;
          font-size: 14px;
        }

        .contract-address {
          font-family: 'Monaco', 'Consolas', monospace;
          background: rgba(59, 130, 246, 0.1);
          padding: 2px 6px;
          border-radius: 4px;
          color: #3b82f6;
        }

        .auth-note {
          background: #f0f9ff;
          border: 1px solid #bae6fd;
          border-radius: 6px;
          padding: 12px;
          margin: 16px 0 0 0;
          color: #0c4a6e;
          font-size: 13px;
          line-height: 1.4;
        }

        .confirmation-buttons {
          display: flex;
          gap: 12px;
          justify-content: center;
        }

        .reject-button,
        .approve-button {
          padding: 12px 24px;
          border: none;
          border-radius: 8px;
          cursor: pointer;
          font-size: 14px;
          font-weight: 600;
          transition: all 0.2s;
          min-width: 100px;
        }

        .reject-button {
          background: #f9fafb;
          color: #6b7280;
          border: 1px solid #d1d5db;
        }

        .reject-button:hover {
          background: #f3f4f6;
          color: #374151;
        }

        .approve-button {
          background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
          color: white;
          box-shadow: 0 4px 12px rgba(102, 126, 234, 0.3);
        }

        .approve-button:hover {
          transform: translateY(-1px);
          box-shadow: 0 6px 16px rgba(102, 126, 234, 0.4);
        }
      `}</style>
    </div>
  );
};

export default GianoConnectionModal; 