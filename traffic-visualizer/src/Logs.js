import * as React from "react";
import PropTypes from "prop-types";
import {
  Box,
  Tabs,
  Tab,
  Select,
  MenuItem,
  InputLabel,
  FormControl,
  CircularProgress,
  Chip,
  Paper,
  Stack,
  TextField,
  Button,
} from "@mui/material";
import { DataGrid } from "@mui/x-data-grid";
import dayjs from "dayjs";

function CustomTabPanel(props) {
  const { children, value, index, ...other } = props;
  return (
    <div role="tabpanel" hidden={value !== index} {...other}>
      {value === index && <Box sx={{ p: 3 }}>{children}</Box>}
    </div>
  );
}

CustomTabPanel.propTypes = {
  children: PropTypes.node,
  index: PropTypes.number.isRequired,
  value: PropTypes.number.isRequired,
};

const getLevelColor = (level) => {
  switch (level.toUpperCase()) {
    case "ERROR":
      return "error";
    case "WARN":
      return "warning";
    case "DEBUG":
      return "info";
    case "INFO":
    default:
      return "success";
  }
};

const formatDateForInput = (date) => dayjs(date).format("YYYY-MM-DDTHH:mm");

export default function Logs() {
  const [tabIndex, setTabIndex] = React.useState(0);
  const [logs, setLogs] = React.useState([]);
  const [loading, setLoading] = React.useState(true);
  const [selectedLevel, setSelectedLevel] = React.useState("ALL");

  const [startTime, setStartTime] = React.useState(
    formatDateForInput(dayjs().startOf("day"))
  );
  const [endTime, setEndTime] = React.useState(formatDateForInput(dayjs()));
  const [selectedButton, setSelectedButton] = React.useState("today");

  const handleTabChange = (event, newValue) => setTabIndex(newValue);

  const setToday = () => {
    setSelectedButton("today");
    setStartTime(formatDateForInput(dayjs().startOf("day")));
    setEndTime(formatDateForInput(dayjs()));
  };

  const setYesterday = () => {
    setSelectedButton("yesterday");
    setStartTime(formatDateForInput(dayjs().subtract(1, "day").startOf("day")));
    setEndTime(formatDateForInput(dayjs().subtract(1, "day").endOf("day")));
  };

  React.useEffect(() => {
    setLoading(true);
    fetch("http://localhost:4000/logs")
      .then((res) => res.json())
      .then((data) => {
        console.log(data);
        const enriched = data.map((log, i) => ({
          id: log.id || i,
          timestamp: log.timestamp,
          level: log.level,
          message: log.message,
        }));
        setLogs(enriched);
      })
      .catch((err) => console.error("Failed to fetch logs:", err))
      .finally(() => setLoading(false));
  }, []);
  const filteredLogs = logs.filter((log) => {
    const logTime = dayjs(log.timestamp);
    const isInDateRange =
      logTime.isAfter(dayjs(startTime)) && logTime.isBefore(dayjs(endTime));
    const matchesLevel =
      selectedLevel === "ALL" || log.level.toUpperCase() === selectedLevel;
    return isInDateRange && matchesLevel;
  });

  const logColumns = [
    {
      field: "timestamp",
      headerName: "Time",
      width: 220
    },
    {
      field: "level",
      headerName: "Level",
      width: 120,
      renderCell: (params) => (
        <Chip
          label={params.value}
          size="small"
          color={getLevelColor(params.value)}
          variant="outlined"
        />
      ),
    },
    {
      field: "message",
      headerName: "Message",
      flex: 1,
    },
  ];

  return (
    <Box sx={{ width: "100%" }}>
      <Tabs value={tabIndex} onChange={handleTabChange}>
        <Tab label="Logs" />
      </Tabs>

      <CustomTabPanel value={tabIndex} index={0}>
        <Stack spacing={2} mb={3}>
          {/* Time and Level Filters */}
          <Stack
            direction="row"
            spacing={2}
            alignItems="center"
            flexWrap="wrap"
          >
            <TextField
              label="Start Time"
              type="datetime-local"
              size="small"
              value={startTime}
              onChange={(e) => {
                setStartTime(e.target.value);
                setSelectedButton(null);
              }}
              InputLabelProps={{ shrink: true }}
            />
            <TextField
              label="End Time"
              type="datetime-local"
              size="small"
              value={endTime}
              onChange={(e) => {
                setEndTime(e.target.value);
                setSelectedButton(null);
              }}
              InputLabelProps={{ shrink: true }}
            />
            <Button
              variant={selectedButton === "today" ? "contained" : "outlined"}
              onClick={setToday}
            >
              Today
            </Button>
            <Button
              variant={
                selectedButton === "yesterday" ? "contained" : "outlined"
              }
              onClick={setYesterday}
            >
              Yesterday
            </Button>

            <FormControl size="small" sx={{ minWidth: 180 }}>
              <InputLabel id="log-filter-label">Filter by Level</InputLabel>
              <Select
                labelId="log-filter-label"
                value={selectedLevel}
                label="Filter by Level"
                onChange={(e) => setSelectedLevel(e.target.value)}
              >
                <MenuItem value="ALL">All</MenuItem>
                <MenuItem value="INFO">Info</MenuItem>
                <MenuItem value="WARN">Warn</MenuItem>
                <MenuItem value="ERROR">Error</MenuItem>
                <MenuItem value="DEBUG">Debug</MenuItem>
              </Select>
            </FormControl>
          </Stack>
        </Stack>

        <Paper
          elevation={4}
          sx={{
            height: 600,
            width: "100%",
            p: 2,
            borderRadius: 2,
            background: "#fafafa",
          }}
        >
          {loading ? (
            <Box sx={{ display: "flex", justifyContent: "center", mt: 4 }}>
              <CircularProgress />
            </Box>
          ) : (
            <DataGrid
              rows={filteredLogs}
              columns={logColumns}
              pageSize={10}
              sx={{
                border: "none",
                fontFamily: "Roboto, sans-serif",
                "& .MuiDataGrid-row:hover": {
                  backgroundColor: "#f0f0f0",
                },
              }}
              disableRowSelectionOnClick
            />
          )}
        </Paper>
      </CustomTabPanel>
    </Box>
  );
}
