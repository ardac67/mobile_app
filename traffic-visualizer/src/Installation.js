import React from "react";
import { Box, Typography, Button, Stack, Divider } from "@mui/material";
import DownloadIcon from "@mui/icons-material/Download";

function Installation() {
  const handleDownload = () => {
    window.open("/TrafficService.zip", "_blank");
  };
  return (
    <Box sx={{ p: 4 }}>
      <Typography variant="h4" gutterBottom>
        Installation Guide
      </Typography>

      <Typography variant="body1" gutterBottom>
        This tool installs the background traffic classification service on your
        Windows machine. Please follow the steps below.
      </Typography>

      <Divider sx={{ my: 3 }} />

      <Stack spacing={2}>
        <Typography variant="h6">Steps:</Typography>
        <Typography>
          1️⃣ Make sure Python and required packages are installed.
        </Typography>
        <Typography>
          2️⃣ Download and run the <code>run.bat</code> file as administrator.
        </Typography>
        <Typography>
          3️⃣ The service will auto-start and begin capturing traffic.
        </Typography>
      </Stack>
      <div
        style={{
          marginTop: "20px",
        }}
      >
        <a href="/TrafficService.zip" download>
          <Button variant="contained" startIcon={<DownloadIcon />}>
            Download Service Package
          </Button>
        </a>
      </div>
    </Box>
  );
}

export default Installation;
