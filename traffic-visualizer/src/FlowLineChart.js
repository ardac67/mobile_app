import {
    LineChart,
    Line,
    XAxis,
    YAxis,
    Tooltip,
    CartesianGrid,
    ResponsiveContainer,
    Legend,
  } from "recharts";
  
  const getTimeLabel = (timestamp) =>
    new Date(timestamp).toLocaleTimeString([], {
      hour: "2-digit",
      minute: "2-digit",
      hour12: false,
    });
  
  
  export function FlowLineChart({ classes }) {
    if (!classes || !classes.length) return null;
  
    const sortedFlows = [...classes].sort(
      (a, b) => new Date(a.createdAt) - new Date(b.createdAt)
    );
  
    // Extract unique IPs and time labels
    const sourceIPs = Array.from(new Set(sortedFlows.map((f) => f.sourceIP)));
    const timeLabels = Array.from(
      new Set(sortedFlows.map((f) => getTimeLabel(f.createdAt)))
    );
  
    // Build a fast lookup: { time -> { sourceIP -> totalBytes } }
    const lookup = new Map();
  
    sortedFlows.forEach((flow) => {
      const time = getTimeLabel(flow.createdAt);
      if (!lookup.has(time)) lookup.set(time, {});
      lookup.get(time)[flow.sourceIP] = flow.metrics.totalBytes;
    });
  
    // Now construct final chart data efficiently
    const data = timeLabels.map((time) => {
      const entry = { time };
      const values = lookup.get(time) || {};
      sourceIPs.forEach((ip) => {
        entry[ip] = values[ip] || null;
      });
      return entry;
    });
  
    return (
      <>
        <ResponsiveContainer width="100%" height={350}>
          <LineChart data={data}>
            <CartesianGrid strokeDasharray="3 3" />
            <XAxis dataKey="time" />
            <YAxis />
            <Tooltip
              formatter={(value) =>
                value ? `${value.toLocaleString()} bytes` : "No data"
              }
            />
            <Legend />
            {sourceIPs.map((ip, index) => (
              <Line
                key={ip}
                type="monotone"
                dataKey={ip}
                stroke={`hsl(${(index * 60) % 360}, 70%, 50%)`}
                strokeWidth={2}
                dot={false}
                connectNulls
              />
            ))}
          </LineChart>
        </ResponsiveContainer>
      </>
    );
  }
  