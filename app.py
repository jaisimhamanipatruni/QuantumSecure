import streamlit as st
import wntr
import pandas as pd
import matplotlib.pyplot as plt
from pyvis.network import Network
import tempfile
import streamlit.components.v1 as components

# -------------------------------
# PAGE CONFIG
# -------------------------------
st.set_page_config(
    page_title="WDN CPS Security Testbed",
    layout="wide"
)

st.markdown(
    """
    <h2 style='text-align:center;'>WDN Cyber-Physical Security Experiment Platform</h2>
    <p style='text-align:center;'>
    Designed by <b>Jaisimha Manipatruni</b>, IIPE Visakhapatnam
    </p>
    <hr>
    """,
    unsafe_allow_html=True
)

# -------------------------------
# UPLOAD MODEL
# -------------------------------
uploaded_file = st.file_uploader("Upload EPANET (.inp) file", type=["inp"])

if not uploaded_file:
    st.info("Upload an EPANET .inp file to begin")
    st.stop()

with open("model.inp", "wb") as f:
    f.write(uploaded_file.getbuffer())

wn_base = wntr.network.WaterNetworkModel("model.inp")

# -------------------------------
# NETWORK VIEW
# -------------------------------
st.subheader("Water Distribution Network")

net = Network(height="450px", width="100%", directed=False)
net.barnes_hut()

for name, node in wn_base.nodes():
    color = "skyblue"
    if node.node_type == "Tank":
        color = "green"
    elif node.node_type == "Reservoir":
        color = "red"
    net.add_node(name, label=f"{name}\n({node.node_type})", color=color)

for name, link in wn_base.links():
    net.add_edge(link.start_node_name, link.end_node_name, label=name)

tmp = tempfile.NamedTemporaryFile(delete=False, suffix=".html")
net.save_graph(tmp.name)
components.html(open(tmp.name).read(), height=470)

# -------------------------------
# EXPERIMENT SETUP
# -------------------------------
st.subheader("Attack Configuration")

node_id = st.selectbox("Select Tank for Analysis / Attack", wn_base.tank_name_list)

attack_type = st.selectbox(
    "Attack Type",
    ["None", "False Data Injection (FDI)", "Denial of Service (DoS)"]
)

fdi_bias = st.slider("FDI Demand Bias (%)", -80, 80, 40)
dos_severity = st.slider("DoS Severity (Demand Reduction %)", 0, 100, 80)

# -------------------------------
# SIMULATION FUNCTION
# -------------------------------
def run_sim(wn):
    wn.options.time.duration = 24 * 3600
    wn.options.time.hydraulic_timestep = 3600
    sim = wntr.sim.EpanetSimulator(wn)
    return sim.run_sim()

# -------------------------------
# PRE-ATTACK SIMULATION
# -------------------------------
st.subheader("Running Pre-Attack Simulation")
pre_results = run_sim(wn_base)
pre_level = pre_results.node["level"].loc[:, node_id]

# -------------------------------
# DURING-ATTACK SIMULATION
# -------------------------------
wn_attack = wntr.network.WaterNetworkModel("model.inp")

if attack_type == "False Data Injection (FDI)":
    tank = wn_attack.get_node(node_id)
    tank.base_demand *= (1 + fdi_bias / 100)

elif attack_type == "Denial of Service (DoS)":
    tank = wn_attack.get_node(node_id)
    tank.base_demand *= (1 - dos_severity / 100)

st.subheader("Running During-Attack Simulation")
during_results = run_sim(wn_attack)
during_level = during_results.node["level"].loc[:, node_id]

# -------------------------------
# POST-ATTACK SIMULATION
# -------------------------------
st.subheader("Running Post-Attack Simulation")
post_results = run_sim(wn_base)
post_level = post_results.node["level"].loc[:, node_id]

# -------------------------------
# PLOTTING
# -------------------------------
st.subheader("Tank Level Response")

col1, col2, col3 = st.columns(3)

with col1:
    st.markdown("**Pre-Attack**")
    fig, ax = plt.subplots()
    pre_level.plot(ax=ax, color="blue")
    ax.set_ylabel("Tank Level")
    ax.grid(True)
    st.pyplot(fig)

with col2:
    st.markdown("**During Attack**")
    fig, ax = plt.subplots()
    during_level.plot(ax=ax, color="red")
    ax.set_ylabel("Tank Level")
    ax.grid(True)
    st.pyplot(fig)

with col3:
    st.markdown("**Post-Attack**")
    fig, ax = plt.subplots()
    post_level.plot(ax=ax, color="green")
    ax.set_ylabel("Tank Level")
    ax.grid(True)
    st.pyplot(fig)

# -------------------------------
# COMPARISON PLOT
# -------------------------------
st.subheader("Pre vs During vs Post Comparison")

fig, ax = plt.subplots(figsize=(8,4))
pre_level.plot(ax=ax, label="Pre-Attack", linewidth=2)
during_level.plot(ax=ax, label="During Attack", linestyle="--")
post_level.plot(ax=ax, label="Post-Attack", linestyle=":")
ax.set_ylabel("Tank Level")
ax.legend()
ax.grid(True)
st.pyplot(fig)

# -------------------------------
# EXPORT DATA
# -------------------------------
st.subheader("Export Results")

df = pd.DataFrame({
    "Pre_Attack": pre_level,
    "During_Attack": during_level,
    "Post_Attack": post_level
})

st.download_button(
    "Download CSV (Publication Ready)",
    df.to_csv().encode(),
    f"{node_id}_{attack_type.replace(' ', '_')}.csv",
    "text/csv"
)




