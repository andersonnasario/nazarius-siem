import React from 'react';
import { BrowserRouter as Router } from 'react-router-dom';
import { ThemeProvider, createTheme } from '@mui/material/styles';
import CssBaseline from '@mui/material/CssBaseline';
import { Box, Typography, Container, Paper } from '@mui/material';

const darkTheme = createTheme({
  palette: {
    mode: 'dark',
    primary: {
      main: '#90caf9',
    },
    background: {
      default: '#0a1929',
      paper: '#1e293b',
    },
  },
});

function AppTest() {
  return (
    <ThemeProvider theme={darkTheme}>
      <CssBaseline />
      <Router>
        <Container maxWidth="lg" sx={{ mt: 4 }}>
          <Paper sx={{ p: 4 }}>
            <Typography variant="h3" gutterBottom>
              🎉 SIEM Platform
            </Typography>
            <Typography variant="h5" color="primary" gutterBottom>
              Sistema Operacional!
            </Typography>
            <Box sx={{ mt: 3 }}>
              <Typography variant="body1" paragraph>
                ✅ React está funcionando
              </Typography>
              <Typography variant="body1" paragraph>
                ✅ Material-UI está funcionando
              </Typography>
              <Typography variant="body1" paragraph>
                ✅ React Router está funcionando
              </Typography>
              <Typography variant="body1" paragraph>
                ✅ Tema escuro aplicado
              </Typography>
            </Box>
            <Typography variant="body2" color="text.secondary" sx={{ mt: 3 }}>
              Agora vamos carregar a aplicação completa...
            </Typography>
          </Paper>
        </Container>
      </Router>
    </ThemeProvider>
  );
}

export default AppTest;

