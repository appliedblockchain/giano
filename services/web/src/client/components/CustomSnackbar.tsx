import React from 'react';
import { CheckCircle, Error } from '@mui/icons-material';
import { Alert, Snackbar, Typography } from '@mui/material';

export type CustomSnackbarProps = {
  severity?: typeof Alert.prototype.severity;
  message?: string;
  open?: boolean;
  onClose?: () => void;
};

const CustomSnackbar: React.FC<CustomSnackbarProps> = ({ severity, message, open = false, onClose = () => {} }) => {
  const severityIcons = {
    success: <CheckCircle />,
    error: <Error />,
  };

  const icon = severityIcons[severity] || <CheckCircle />;

  return (
    <Snackbar open={open} anchorOrigin={{ vertical: 'bottom', horizontal: 'center' }} autoHideDuration={5000} onClose={onClose}>
      <Alert severity={severity} variant="filled" onClose={onClose} icon={icon}>
        <Typography variant="subtitle2">{message}</Typography>
      </Alert>
    </Snackbar>
  );
};

export default CustomSnackbar;
