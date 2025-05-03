import { PieChart, Pie, Tooltip, Cell, ResponsiveContainer } from "recharts";

const COLORS = ["#0088FE", "#00C49F", "#FFBB28", "#FF8042", "#A28EFF"];

// Custom label inside each pie slice
const renderCustomizedLabel = ({
  cx,
  cy,
  midAngle,
  innerRadius,
  outerRadius,
  percent,
  name,
}) => {
  const radius = innerRadius + (outerRadius - innerRadius) * 0.5;
  const RADIAN = Math.PI / 180;
  const x = cx + radius * Math.cos(-midAngle * RADIAN);
  const y = cy + radius * Math.sin(-midAngle * RADIAN);

  return (
    <text
      x={x}
      y={y}
      fill="black"
      textAnchor="middle"
      dominantBaseline="central"
      fontSize={12}
    >
      {`${name}\n${(percent * 100).toFixed(1)}%`}
    </text>
  );
};

const renderCustomLabelTemp = ({ name, value, percent }) => {
  return `${name}: ${value.toLocaleString()} (${(percent * 100).toFixed(1)}%)`;
};

export function TrafficPieChart({ classes }) {
  if (!classes || !classes.length) return null;

  const trafficByClass = {};

  classes.forEach((flow) => {
    const topClass = flow.predictedClass.classes.reduce((a, b) =>
      a.probability > b.probability ? a : b
    );
    const bytes = flow.metrics.totalBytes || 0;

    if (!trafficByClass[topClass.label]) {
      trafficByClass[topClass.label] = 0;
    }
    trafficByClass[topClass.label] += bytes;
  });

  const data = Object.entries(trafficByClass).map(([label, value]) => ({
    name: label,
    value,
  }));

  return (
    <ResponsiveContainer width="100%" height={350}>
      <PieChart>
        <Pie
          data={data}
          dataKey="value"
          nameKey="name"
          outerRadius={150}
          label={renderCustomizedLabel}
          labelLine={false}
        >
          {data.map((_, index) => (
            <Cell key={index} fill={COLORS[index % COLORS.length]} />
          ))}
        </Pie>
        <Tooltip
          formatter={(value, name) => [
            `${Number(value).toLocaleString()} bytes`,
            name,
          ]}
        />
      </PieChart>
    </ResponsiveContainer>
  );
}
