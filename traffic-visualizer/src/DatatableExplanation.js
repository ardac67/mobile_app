import React, { useState, useEffect } from "react";
import Box from "@mui/material/Box";
import { DataGrid } from "@mui/x-data-grid";
import LoadingStuff from "./LoadingStuff";
import explanationJson from "./explanations.json";
import { TextField, Button, Stack } from "@mui/material";
import dayjs from "dayjs";
import isSameOrAfter from "dayjs/plugin/isSameOrAfter";
import isSameOrBefore from "dayjs/plugin/isSameOrBefore";

// Extend dayjs with plugins
dayjs.extend(isSameOrAfter);
dayjs.extend(isSameOrBefore);

const columns = [
  { field: "id", headerName: "ID", width: 20 },
  { field: "sourceIP", headerName: "Source IP", width: 120 },
  { field: "destinationIP", headerName: "Destination IP", width: 120 },
  { field: "confidence", headerName: "Confidence", width: 80, type: "number" },
  { field: "sourcePort", headerName: "Source Port", width: 100, type: "number" },
  { field: "explanation", headerName: "Explanation", width: 200 },
  { field: "interval", headerName: "Interval", width: 100 },
  {
    field: "predictedClass",
    headerName: "Top Prediction",
    width: 150,
    valueGetter: (params) => {
      if (!params || !params.classes || params.classes.length === 0) {
        return "Unknown";
      }
      return params.classes[0].label;
    },
  },
  {
    field: "createdAt",
    headerName: "Created At",
    width: 200,
    valueGetter: (params) => {
      if (!params) return "";
      return new Date(params).toLocaleString();
    },
  },
];

function formatDateForInput(date) {
  return dayjs(date).format("YYYY-MM-DDTHH:mm");
}

export default function DatatableExplanation() {
  const [rows, setRows] = useState([]);
  const [loading, setLoading] = useState(true);
  const [startTime, setStartTime] = useState(formatDateForInput(dayjs().startOf("day")));
  const [endTime, setEndTime] = useState(formatDateForInput(dayjs()));
  const [selectedButton, setSelectedButton] = useState("today");

  const fetchData = () => {
    setLoading(true);
    fetch("http://localhost:4000/predictions") // Replace with your real API
      .then((response) => {
        if (!response.ok) throw new Error("Network response was not ok");
        
        return response.json();
      })
      .then((data) => {
        console.log(data)
        const filtered = data.filter((row) => {
          const created = dayjs(row.createdAt);
          return created.isSameOrAfter(dayjs(startTime)) && created.isSameOrBefore(dayjs(endTime));
        });

        const enrichedData = filtered.map((row) => {
          const topLabel = row.predictedClass.classes?.[0]?.label ?? "Unknown";
          return {
            ...row,
            explanation: explanationJson[topLabel] || "No explanation",
            interval: "30s",
          };
        });
        setRows(enrichedData);
        setLoading(false);
      })
      .catch((error) => {
        console.error("Fetch error:", error);
        setLoading(false);
      });
  };

  useEffect(() => {
    fetchData();
  }, [startTime, endTime]);

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

  return (
    <Box sx={{ height: 700, width: "100%", p: 2 }}>
      <Stack direction="row" spacing={2} alignItems="center" mb={2}>
        <TextField
          label="Start Time"
          type="datetime-local"
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
          variant={selectedButton === "yesterday" ? "contained" : "outlined"}
          onClick={setYesterday}
        >
          Yesterday
        </Button>
      </Stack>

      {loading ? (
        <LoadingStuff />
      ) : rows.length === 0 ? (
        <div style={{ padding: 20 }}>No Data Available</div>
      ) : (
        <DataGrid
          rows={rows}
          columns={columns}
          pageSizeOptions={[5, 10, 20]}
          disableRowSelectionOnClick
        />
      )}
    </Box>
  );
}
