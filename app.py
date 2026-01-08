import streamlit as st
import wntr
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
from pyvis.network import Network
import tempfile
import streamlit.components.v1 as components

# -------------------------------
# APP CONFIG
# -------------------------------
st.set_page_config(layout="wide")
st.title("WDN Cyber-Physical Security Experiment Platform")

# -------------------------------
# UPLOAD MODEL
# -------------------------------
uploaded_file = st.file_uploader("Upload EPANET .inp file", type=["inp"])

if not uploaded_file:
    st.info("Upload an EPANET .inp file to begin")
    st.stop()

with open("model.inp", "wb") as f:
    f.write(uploaded_file.getbuffer())

wn = wntr.network.WaterNetworkModel("model.inp")
st.success("EPANET model loaded")

# -------------------------------
# NETWORK VISUALIZATION
# -------------------------------
st.subheader("Water Distribution Network")

net = Network(height="500px", width="100%", directed=False)
net.barnes_hut()

for name, node in wn.nodes():
    color = "blue"
    if node.node_type == "Tank":
        color = "green"
    elif node.node_type == "Reservoir":
        color = "red"
    net.add_node(name, label=f"{name}\n({node.node_type})", color=color)

for name, link in wn.links():
    net.add_edge(link.start_node_name, link.end_node_name, label=name)

tmp = tempfile.NamedTemporaryFile(delete=False, suffix=".html")
net.save_graph(tmp.name)
components.html(open(tmp.name).read(), height=520)

# -------------------------------
# EXPERIMENT SETUP
# -------------------------------
st.subheader("Experiment Configuration")

node_id = st.selectbox("Select node for monitoring / attack", wn.node_name_list)
node = wn.get_node(node_id)

attack_type = st.selectbox(
    "Attack type",
    ["None", "False Data Injection (FDI)", "Denial of Service (DoS)"]
)

t_start = st.number_input("Attack start time (hours)", 0.0, 24.0, 6.0)
t_end = st.number_input("Attack end time (hours)", 0.0, 24.0, 12.0)

fdi_bias = st.slider("FDI bias (%)", -50, 50, 30)

# -------------------------------
# SIMULATION PARAMETERS
# -------------------------------
wn.options.time.duration = 24 * 3600
wn.options.time.hydraulic_timestep = 3600

# -------------------------------
# BASELINE SIMULATION
# -------------------------------
sim = wntr.sim.EpanetSimulator(wn)
baseline = sim.run_sim()

if node.node_type == "Tank":
    baseline_series = baseline.node["level"].loc[:, node_id]
    ylabel = "Tank Level"
else:
    baseline_series = baseline.node["pressure"].loc[:, node_id]
    ylabel = "Pressure"

# -------------------------------
# ATTACK SIMULATION
# -------------------------------
wn_attack = wntr.network.WaterNetworkModel("model.inp")
wn_attack.options.time.duration = 24 * 3600
wn_attack.options.time.hydraulic_timestep = 3600

time_hours = baseline_series.index / 3600
attack_mask = (time_hours >= t_start) & (time_hours <= t_end)

attack_series = baseline_series.copy()

if attack_type != "None" and node.node_type == "Tank":

    if attack_type == "False Data Injection (FDI)":
        attack_series.loc[attack_mask] *= (1 + fdi_bias / 100)

    elif attack_type == "Denial of Service (DoS)":
        attack_series.loc[attack_mask] *= 0.2

# -------------------------------
# SEGMENT DATA
# -------------------------------
pre_attack = attack_series.loc[time_hours < t_start]
during_attack = attack_series.loc[attack_mask]
post_attack = attack_series.loc[time_hours > t_end]

# -------------------------------
# PLOTS
# -------------------------------
st.subheader("Results: Pre / During / Post Attack")

# Plot 1: Full comparison
fig1, ax1 = plt.subplots(figsize=(8, 4))
baseline_series.plot(ax=ax1, label="Baseline", linewidth=2)
attack_series.plot(ax=ax1, label="With Attack", linestyle="--")
ax1.axvspan(t_start*3600, t_end*3600, color="red", alpha=0.2, label="Attack Window")
ax1.set_ylabel(ylabel)
ax1.set_xlabel("Time (seconds)")
ax1.legend()
ax1.grid(True)
st.pyplot(fig1)

# Plot 2: Delta plot
fig2, ax2 = plt.subplots(figsize=(8, 3))
(attack_series - baseline_series).plot(ax=ax2, color="purple")
ax2.axhline(0, color="black")
ax2.set_ylabel("Deviation")
ax2.set_title("Attack Impact (Δ)")
ax2.grid(True)
st.pyplot(fig2)

# Plot 3: Segmented plot
fig3, ax3 = plt.subplots(figsize=(8, 4))
pre_attack.plot(ax=ax3, label="Pre-Attack")
during_attack.plot(ax=ax3, label="During Attack")
post_attack.plot(ax=ax3, label="Post-Attack")
ax3.set_ylabel(ylabel)
ax3.legend()
ax3.grid(True)
st.pyplot(fig3)

# -------------------------------
# EXPORT DATA
# -------------------------------
st.subheader("Export Results")

full_df = pd.DataFrame({
    "baseline": baseline_series,
    "attack": attack_series
})

segmented_df = pd.concat(
    [pre_attack, during_attack, post_attack],
    keys=["pre", "during", "post"]
)

st.download_button(
    "Download Full Time-Series CSV",
    full_df.to_csv().encode(),
    "full_results.csv",
    "text/csv"
)

st.download_button(
    "Download Segmented CSV",
    segmented_df.to_csv().encode(),
    "segmented_results.csv",
    "text/csv"
)



