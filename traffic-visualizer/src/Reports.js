import * as React from "react";
import PropTypes from "prop-types";
import Tabs from "@mui/material/Tabs";
import Tab from "@mui/material/Tab";
import Box from "@mui/material/Box";
import DatatableMetrics from "./DatatableMetrics";
import Badge from "@mui/material/Badge";
import NetworkCheckIcon from "@mui/icons-material/NetworkCheck";
import DatatableExplanation from "./DatatableExplanation";

function CustomTabPanel(props) {
  const { children, value, index, ...other } = props;

  return (
    <div
      role="tabpanel"
      hidden={value !== index}
      id={`simple-tabpanel-${index}`}
      aria-labelledby={`simple-tab-${index}`}
      {...other}
    >
      {value === index && <Box sx={{ p: 3 }}>{children}</Box>}
    </div>
  );
}

CustomTabPanel.propTypes = {
  children: PropTypes.node,
  index: PropTypes.number.isRequired,
  value: PropTypes.number.isRequired,
};

function a11yProps(index) {
  return {
    id: `simple-tab-${index}`,
    "aria-controls": `simple-tabpanel-${index}`,
  };
}

export default function Logs() {
  const [value, setValue] = React.useState(0);

  const handleChange = (event, newValue) => {
    setValue(newValue);
  };

  return (
    <Box sx={{ width: "100%" }}>
      <div style={{
        display:'flex',
        flexDirection : 'row',
        alignItems:'center',
        gap:'10px'
      }}>
        <Badge color="primary">
          <NetworkCheckIcon color="action" />
        </Badge>
        <h2>Appose Reports</h2>
      </div>
      <Box sx={{ borderBottom: 1, borderColor: "divider" }}>
        <Tabs
          value={value}
          onChange={handleChange}
          aria-label="basic tabs example"
        >
          <Tab label="Network Metrics" {...a11yProps(0)} />
          <Tab label="Predicted Network Requests" {...a11yProps(1)} />
        </Tabs>
      </Box>
      <CustomTabPanel value={value} index={0}>
        <DatatableMetrics></DatatableMetrics>
      </CustomTabPanel>
      <CustomTabPanel value={value} index={1}>
      <DatatableExplanation></DatatableExplanation>
      </CustomTabPanel>
    </Box>
  );
}
