import streamlit as st
import wntr
import pandas as pd
import matplotlib.pyplot as plt
from pyvis.network import Network
import tempfile
import streamlit.components.v1 as components

# =====================================================
# PAGE CONFIG + HEADER
# =====================================================
st.set_page_config(layout="wide", page_title="WDN CPS Security Testbed")

st.markdown(
    """
    <h2 style="text-align:center;">WDN Cyber-Physical Security Experiment Platform</h2>
    <p style="text-align:center;">
    Designed by <b>Jaisimha Manipatruni</b>, IIPE Visakhapatnam
    </p>
    <hr>
    """,
    unsafe_allow_html=True
)

# =====================================================
# HELPER FUNCTIONS
# =====================================================
def ieee_style(ax, xlabel, ylabel):
    ax.set_xlabel(xlabel, fontsize=10)
    ax.set_ylabel(ylabel, fontsize=10)
    ax.tick_params(labelsize=9)
    ax.grid(True)

def get_tank_level(results, wn, tank_id):
    head = results.node["head"].loc[:, tank_id]
    elevation = wn.get_node(tank_id).elevation
    return head - elevation

def run_simulation(wn):
    wn.options.time.duration = 24 * 3600
    wn.options.time.hydraulic_timestep = 3600
    sim = wntr.sim.EpanetSimulator(wn)
    return sim.run_sim()

# =====================================================
# UPLOAD EPANET MODEL
# =====================================================
uploaded_file = st.file_uploader("Upload EPANET (.inp) file", type=["inp"])

if not uploaded_file:
    st.info("Upload an EPANET .inp file to begin")
    st.stop()

with open("model.inp", "wb") as f:
    f.write(uploaded_file.getbuffer())

wn_base = wntr.network.WaterNetworkModel("model.inp")

# =====================================================
# NETWORK VISUALIZATION
# =====================================================
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

# =====================================================
# ATTACK CONFIGURATION
# =====================================================
st.subheader("Attack Configuration")

component_type = st.selectbox(
    "Component Type",
    ["Junction", "Tank", "Pump", "Valve"]
)

if component_type == "Junction":
    component_id = st.selectbox("Select Junction", wn_base.junction_name_list)
elif component_type == "Tank":
    component_id = st.selectbox("Select Tank", wn_base.tank_name_list)
elif component_type == "Pump":
    component_id = st.selectbox("Select Pump", wn_base.pump_name_list)
else:
    component_id = st.selectbox("Select Valve", wn_base.valve_name_list)

attack_type = st.selectbox(
    "Attack Type",
    ["None", "False Data Injection (FDI)", "Denial of Service (DoS)"]
)

t_start = st.number_input("Attack start time (seconds)", 0, 86400, 3600)
attack_duration = st.number_input("Attack duration (seconds)", 0, 86400, 3600)
t_end = t_start + attack_duration

attack_magnitude = st.slider("Attack Magnitude (%)", -80, 80, 40)

# =====================================================
# SIMULATE BUTTON
# =====================================================
run_sim = st.button("▶ Run Simulation")

if not run_sim:
    st.stop()

# =====================================================
# PRE-ATTACK SIMULATION
# =====================================================
pre_results = run_simulation(wn_base)

# =====================================================
# DURING-ATTACK SIMULATION
# =====================================================
wn_attack = wntr.network.WaterNetworkModel("model.inp")

# ---- FDI (Demand falsification – WNTR legal)
if attack_type == "False Data Injection (FDI)" and component_type in ["Junction", "Tank"]:
    node = wn_attack.get_node(component_id)
    factor = 1 + attack_magnitude / 100
    node.demand_timeseries_list[0].base_value *= factor

# ---- DoS (Time-based actuator denial)
elif attack_type == "Denial of Service (DoS)" and component_type in ["Pump", "Valve"]:
    link = wn_attack.get_link(component_id)

    dos_start = wntr.network.controls.Control(
        wntr.network.controls.SimTimeCondition(wn_attack, ">=", t_start),
        wntr.network.controls.LinkStatusAction(link, 0)
    )
    wn_attack.add_control("dos_start", dos_start)

    dos_end = wntr.network.controls.Control(
        wntr.network.controls.SimTimeCondition(wn_attack, ">=", t_end),
        wntr.network.controls.LinkStatusAction(link, 1)
    )
    wn_attack.add_control("dos_end", dos_end)

during_results = run_simulation(wn_attack)

# =====================================================
# POST-ATTACK SIMULATION
# =====================================================
post_results = run_simulation(wn_base)

# =====================================================
# METRIC EXTRACTION
# =====================================================
if component_type == "Tank":
    pre = get_tank_level(pre_results, wn_base, component_id)
    during = get_tank_level(during_results, wn_attack, component_id)
    post = get_tank_level(post_results, wn_base, component_id)
    ylabel = "Tank Level (m)"
else:
    pre = pre_results.node["pressure"].loc[:, component_id]
    during = during_results.node["pressure"].loc[:, component_id]
    post = post_results.node["pressure"].loc[:, component_id]
    ylabel = "Pressure (m)"

# =====================================================
# PLOTS
# =====================================================
st.subheader("Results Visualization")

col1, col2, col3 = st.columns(3)

with col1:
    st.markdown("**Pre-Attack**")
    fig, ax = plt.subplots()
    pre.plot(ax=ax)
    ieee_style(ax, "Time (s)", ylabel)
    st.pyplot(fig)

with col2:
    st.markdown("**During Attack**")
    fig, ax = plt.subplots()
    during.plot(ax=ax, color="red")
    ieee_style(ax, "Time (s)", ylabel)
    st.pyplot(fig)

with col3:
    st.markdown("**Post-Attack**")
    fig, ax = plt.subplots()
    post.plot(ax=ax, color="green")
    ieee_style(ax, "Time (s)", ylabel)
    st.pyplot(fig)

# ---- Comparison plot
st.subheader("Pre vs During vs Post Comparison")

fig, ax = plt.subplots(figsize=(8, 4))
pre.plot(ax=ax, label="Pre-Attack", linewidth=2)
during.plot(ax=ax, label="During Attack", linestyle="--")
post.plot(ax=ax, label="Post-Attack", linestyle=":")
ieee_style(ax, "Time (s)", ylabel)
ax.legend()
st.pyplot(fig)

# =====================================================
# EXPORT CSV
# =====================================================
st.subheader("Export Publication-Ready Data")

df = pd.DataFrame({
    "Time_s": pre.index,
    "Pre_Attack": pre.values,
    "During_Attack": during.values,
    "Post_Attack": post.values
})

st.download_button(
    "Download CSV (IEEE-ready)",
    df.to_csv(index=False).encode(),
    f"{component_id}_{attack_type.replace(' ', '_')}.csv",
    "text/csv"
)







