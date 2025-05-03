import * as React from 'react';
import Box from '@mui/material/Box';
import Card from '@mui/material/Card';
import CardContent from '@mui/material/CardContent';
import Typography from '@mui/material/Typography';
import TrendingUpIcon from '@mui/icons-material/TrendingUp';
import DataUsageIcon from '@mui/icons-material/DataUsage';
import AccessTimeIcon from '@mui/icons-material/AccessTime';
import DnsIcon from '@mui/icons-material/Dns';
import LinearProgress from '@mui/material/LinearProgress';
import Tooltip from '@mui/material/Tooltip';

const iconMap = {
  packets: <DnsIcon fontSize="large" sx={{ color: '#1976d2' }} />,
  rate: <TrendingUpIcon fontSize="large" sx={{ color: '#2e7d32' }} />,
  time: <AccessTimeIcon fontSize="large" sx={{ color: '#f57c00' }} />,
  size: <DataUsageIcon fontSize="large" sx={{ color: '#6a1b9a' }} />,
};

export default function CardComponent({
  title,
  value,
  unit,
  type = 'rate',
  description = '',
  max = 100,
}) {
  // Clamp percentage for progress bar
  const percentage = Math.min((parseFloat(value) / max) * 100, 100);

  return (
    <Box sx={{ minWidth: 250, flex: 1 }}>
      <Card
        variant="outlined"
        sx={{
          p: 2,
          borderRadius: 3,
          boxShadow: 4,
          background: 'linear-gradient(135deg, #f3f3f3, #ffffff)',
          transition: 'transform 0.2s ease, box-shadow 0.2s ease',
          '&:hover': {
            transform: 'scale(1.03)',
            boxShadow: 6,
          },
        }}
      >
        <CardContent>
          <Box sx={{ display: 'flex', alignItems: 'center', gap: 2, mb: 1 }}>
            {iconMap[type]}
            <Box>
              <Typography
                sx={{ fontSize: 18, fontWeight: 600, color: 'text.secondary' }}
              >
                {title}
              </Typography>
              {description && (
                <Typography
                  sx={{ fontSize: 12, color: 'text.disabled', mt: 0.5 }}
                >
                  {description}
                </Typography>
              )}
            </Box>
          </Box>

          <Tooltip title={`Exact value: ${value} ${unit}`}>
            <Typography
              variant="h3"
              component="div"
              sx={{
                mt: 1,
                fontWeight: 'bold',
                color: '#333',
                fontSize: '2.2rem',
              }}
            >
              {value} <span style={{ fontSize: 20, color: '#666' }}>{unit}</span>
            </Typography>
          </Tooltip>

          <Box sx={{ mt: 2 }}>
            <LinearProgress
              variant="determinate"
              value={percentage}
              sx={{
                height: 8,
                borderRadius: 5,
                backgroundColor: '#e0e0e0',
                '& .MuiLinearProgress-bar': {
                  backgroundColor: type === 'rate' ? '#2e7d32' :
                    type === 'packets' ? '#1976d2' :
                    type === 'time' ? '#f57c00' :
                    '#6a1b9a',
                },
              }}
            />
          </Box>
        </CardContent>
      </Card>
    </Box>
  );
}
