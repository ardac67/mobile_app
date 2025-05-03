import React, { useEffect, useState } from "react";
import { Box } from "@mui/material";
import CardComponent from "./CardComponent";
import { PredBarChart } from "PredBarChart";
import { TrafficPieChart } from "TrafficPieChart";
import Card from "@mui/material/Card";
import { FlowLineChart } from "FlowLineChart";
import { ClassOverTimeByIPChart } from "ClassOverTimeByIPChart";
import LinearProgress from "@mui/material/LinearProgress";
import DashboardIcon from '@mui/icons-material/Dashboard';

import { TextField, Button, Stack } from "@mui/material";
import dayjs from "dayjs";
import isSameOrAfter from "dayjs/plugin/isSameOrAfter";
import isSameOrBefore from "dayjs/plugin/isSameOrBefore";

dayjs.extend(isSameOrAfter);
dayjs.extend(isSameOrBefore);

const formatDateForInput = (date) => dayjs(date).format("YYYY-MM-DDTHH:mm");

function Dashboard() {
  const [data, setData] = useState([]);
  const [loading, setLoading] = useState(true);

  const [startTime, setStartTime] = useState(
    formatDateForInput(dayjs().startOf("day"))
  );
  const [endTime, setEndTime] = useState(formatDateForInput(dayjs()));
  const [selectedButton, setSelectedButton] = useState("today");

  useEffect(() => {
    setLoading(true);
    fetch("http://localhost:4000/predictions")
      .then((res) => res.json())
      .then((json) => {
        const filtered = json.filter((row) => {
          const created = dayjs(row.createdAt);
          return (
            created.isSameOrAfter(dayjs(startTime)) &&
            created.isSameOrBefore(dayjs(endTime))
          );
        });
        setData(filtered);
      })
      .catch((err) => {
        console.error("Failed to fetch data:", err);
      })
      .finally(() => {
        setLoading(false);
      });
  }, [startTime, endTime]);

  const calculateAverage = (key) => {
    const validData = data.filter(
      (d) => d.metrics && typeof d.metrics[key] === "number"
    );
    if (validData.length === 0) return "N/A";
    const sum = validData.reduce((acc, curr) => acc + curr.metrics[key], 0);
    const avg = sum / validData.length;
    return avg.toFixed(2);
  };

  const totalPackets = calculateAverage("totalPackets");
  const byteRate = calculateAverage("byteRate");
  const flowDuration = calculateAverage("flowDuration");
  const averagePacketSize = calculateAverage("averagePacketSize");

  return (
    <Box sx={{ width: "100%", p: 3 }}>
      {loading && (
        <LinearProgress
          sx={{
            position: "sticky",
            top: 0,
            zIndex: 1000,
            marginBottom: "10px",
          }}
        />
      )}

      <h2 style={{ display: "flex", alignItems: "center", gap: "8px" }}>
        <DashboardIcon style={{ fontSize: "1.5rem", color: "#444" }} />
        Dashboard
      </h2>
      <Stack direction="row" spacing={2} mb={3}>
        <Button
          variant="outlined"
          onClick={() =>
            document
              .getElementById("bar")
              ?.scrollIntoView({ behavior: "smooth" })
          }
        >
          Top Prediction Count
        </Button>
        <Button
          variant="outlined"
          onClick={() =>
            document
              .getElementById("pie")
              ?.scrollIntoView({ behavior: "smooth" })
          }
        >
          Traffic by Predicted Class
        </Button>
        <Button
          variant="outlined"
          onClick={() =>
            document
              .getElementById("line")
              ?.scrollIntoView({ behavior: "smooth" })
          }
        >
          Total Bytes Over Time by Source IP
        </Button>
        <Button
          variant="outlined"
          onClick={() =>
            document
              .getElementById("classbyip")
              ?.scrollIntoView({ behavior: "smooth" })
          }
        >
          Top Class Predictions Grouped By IP
        </Button>
      </Stack>

      <Stack direction="row" spacing={2} alignItems="center" mb={4}>
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
          onClick={() => {
            setSelectedButton("today");
            setStartTime(formatDateForInput(dayjs().startOf("day")));
            setEndTime(formatDateForInput(dayjs()));
          }}
        >
          Today
        </Button>
        <Button
          variant={selectedButton === "yesterday" ? "contained" : "outlined"}
          onClick={() => {
            setSelectedButton("yesterday");
            setStartTime(
              formatDateForInput(dayjs().subtract(1, "day").startOf("day"))
            );
            setEndTime(
              formatDateForInput(dayjs().subtract(1, "day").endOf("day"))
            );
          }}
        >
          Yesterday
        </Button>
      </Stack>
      <div
        style={{
          display: "flex",
          flexDirection: "row",
          gap: "20px",
          flexWrap: "wrap",
        }}
      >
        <CardComponent
          title="Avg. Total Packets"
          value={totalPackets}
          unit="pkts"
          type="packets"
          description="Average over recent flows"
          max={1000}
        />

        <CardComponent
          title="Avg. Byte Rate"
          value={byteRate}
          unit="B/s"
          type="rate"
          description="Network throughput"
          max={20000}
        />

        <CardComponent
          title="Avg. Flow Duration"
          value={flowDuration}
          unit="sec"
          type="time"
          description="Connection lifespan"
          max={60}
        />

        <CardComponent
          title="Avg. Packet Size"
          value={averagePacketSize}
          unit="B"
          type="size"
          description="Data per packet"
          max={1500}
        />
      </div>
      <div
        style={{ marginTop: "100px", display: "flex", flexDirection: "row" }}
      >
        <div
          style={{
            display: "flex",
            flex: "1",
            flexDirection: "column",
          }}
        >
          <Card
            id="bar"
            variant="outlined"
            sx={{
              p: 2,
              borderRadius: 3,
              boxShadow: 4,
              background: "linear-gradient(135deg, #f3f3f3, #ffffff)",
              transition: "transform 0.2s ease, box-shadow 0.2s ease",
              "&:hover": {
                transform: "scale(1.03)",
                boxShadow: 6,
              },
              height: "450px",
            }}
          >
            <h2
              style={{
                textAlign: "center",
                marginBottom: "1rem",
                color: "#444",
              }}
            >
              Top Prediction Count
            </h2>
            <PredBarChart classes={data} />
          </Card>
        </div>
        <div
          style={{
            display: "flex",
            flex: "1",
            flexDirection: "column",
          }}
        >
          <Card
            variant="outlined"
            id="pie"
            sx={{
              p: 2,
              borderRadius: 3,
              boxShadow: 4,
              background: "linear-gradient(135deg, #f3f3f3, #ffffff)",
              transition: "transform 0.2s ease, box-shadow 0.2s ease",
              "&:hover": {
                transform: "scale(1.03)",
                boxShadow: 6,
              },
              marginLeft: "20px",
              height: "450px",
            }}
          >
            <h2
              style={{
                textAlign: "center",
                marginBottom: "1rem",
                color: "#444",
              }}
            >
              Traffic by Predicted Class
            </h2>
            <TrafficPieChart classes={data} />
          </Card>
        </div>
      </div>
      <div
        style={{ marginTop: "100px", display: "flex", flexDirection: "row" }}
      >
        <Card
          variant="outlined"
          id="line"
          sx={{
            p: 2,
            borderRadius: 3,
            boxShadow: 4,
            background: "linear-gradient(135deg, #f3f3f3, #ffffff)",
            transition: "transform 0.2s ease, box-shadow 0.2s ease",
            "&:hover": {
              transform: "scale(1.03)",
              boxShadow: 6,
            },
            width: "100%",
          }}
        >
          <h2
            style={{
              textAlign: "center",
              marginBottom: "1rem",
              color: "#444",
            }}
          >
            Total Bytes Over Time by Source IP
          </h2>
          <FlowLineChart classes={data}></FlowLineChart>
        </Card>
      </div>
      <div
        style={{ marginTop: "100px", display: "flex", flexDirection: "row" }}
      >
        <Card
          id="classbyip"
          variant="outlined"
          sx={{
            p: 2,
            borderRadius: 3,
            boxShadow: 4,
            background: "linear-gradient(135deg, #f3f3f3, #ffffff)",
            transition: "transform 0.2s ease, box-shadow 0.2s ease",
            "&:hover": {
              transform: "scale(1.03)",
              boxShadow: 6,
            },
            width: "100%",
          }}
        >
          <h2
            style={{
              textAlign: "center",
              marginBottom: "1rem",
              color: "#444",
            }}
          >
            Top Class Predictions Grouped By IP
          </h2>
          <ClassOverTimeByIPChart classes={data}></ClassOverTimeByIPChart>
        </Card>
      </div>
    </Box>
  );
}

export default Dashboard;
