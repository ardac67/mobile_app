import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer } from 'recharts';

export function PredBarChart({ classes }) {
  if (!classes || !classes.length) return null;

  const labelCounts = {};

  classes.forEach(flow => {
    const topClass = flow.predictedClass.classes.reduce((a, b) =>
      a.probability > b.probability ? a : b
    );

    if (!labelCounts[topClass.label]) {
      labelCounts[topClass.label] = 0;
    }
    labelCounts[topClass.label] += 1;
  });

  const data = Object.entries(labelCounts).map(([label, count]) => ({
    name: label,
    count,
  }));

  return (
    <ResponsiveContainer width="100%" height={300}>
      <BarChart data={data}>
        <XAxis dataKey="name" />
        <YAxis />
        <Tooltip />
        <Bar dataKey="count" fill="#8884d8" />
      </BarChart>
    </ResponsiveContainer>
  );
}
  
