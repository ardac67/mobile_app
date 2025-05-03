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

// Step 1: Label formatter for class number
const CLASS_LABELS = {};
let classCounter = 1;

const getClassIndex = (label) => {
  if (!CLASS_LABELS[label]) {
    CLASS_LABELS[label] = classCounter++;
  }
  return CLASS_LABELS[label];
};

const getTimeBucket = (timestamp) =>
  new Date(timestamp).toLocaleTimeString([], {
    hour: "2-digit",
    minute: "2-digit",
    hour12: false,
  });

export function ClassOverTimeByIPChart({ classes }) {
  if (!classes || !classes.length) return null;

  // Step 2: Build data points
  const points = classes.map((flow) => {
    const time = getTimeBucket(flow.createdAt);
    const ip = flow.sourceIP;
    const topClass = flow.predictedClass.classes.reduce((a, b) =>
      a.probability > b.probability ? a : b
    ).label;
    return {
      time,
      ip,
      classIndex: getClassIndex(topClass),
      classLabel: topClass,
    };
  });

  // Step 3: Get unique time buckets and IPs
  const timeBuckets = Array.from(new Set(points.map((p) => p.time)));
  const ips = Array.from(new Set(points.map((p) => p.ip)));

  // Step 4: Reshape for recharts (row per time, column per IP)
  const data = timeBuckets.map((time) => {
    const entry = { time };
    ips.forEach((ip) => {
      const match = points.find((p) => p.time === time && p.ip === ip);
      entry[ip] = match ? match.classIndex : null;
    });
    return entry;
  });

  return (
    <>
      <ResponsiveContainer width="100%" height={350}>
        <LineChart data={data}>
          <CartesianGrid strokeDasharray="3 3" />
          <XAxis dataKey="time" />
          <YAxis
            allowDecimals={false}
            tickFormatter={(val) =>
              Object.entries(CLASS_LABELS).find(([, v]) => v === val)?.[0] ||
              val
            }
            tick={{ fontSize: 10 }} // 👈 Set font size here
          />

          <Tooltip
            formatter={(value) =>
              Object.entries(CLASS_LABELS).find(([, v]) => v === value)?.[0]
            }
          />
          <Legend />
          {ips.map((ip, index) => (
            <Line
              key={ip}
              type="monotone"
              dataKey={ip}
              stroke={`hsl(${(index * 60) % 360}, 70%, 50%)`}
              strokeWidth={2}
              dot
              connectNulls
            />
          ))}
        </LineChart>
      </ResponsiveContainer>
    </>
  );
}
