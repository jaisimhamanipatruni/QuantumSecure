import streamlit as st
import wntr
import pandas as pd
import matplotlib.pyplot as plt

# -------------------------------
# Helper functions
# -------------------------------
def get_tank_level(results, wn, tank_id):
    head = results.node["head"].loc[:, tank_id]
    elevation = wn.get_node(tank_id).elevation
    return head - elevation

def ieee_plot_style(ax, xlabel, ylabel, title):
    ax.set_xlabel(xlabel)
    ax.set_ylabel(ylabel)
    ax.set_title(title)
    ax.grid(True)

# -------------------------------
# Load model
# -------------------------------
uploaded_file = st.file_uploader("Upload EPANET (.inp)", type=["inp"])
if not uploaded_file:
    st.stop()

with open("model.inp", "wb") as f:
    f.write(uploaded_file.getbuffer())

wn = wntr.network.WaterNetworkModel("model.inp")

# -------------------------------
# Attack configuration
# -------------------------------
st.subheader("Attack Configuration")

component_type = st.selectbox(
    "Component Type",
    ["Junction", "Tank", "Pump", "Valve"]
)

if component_type == "Junction":
    component_id = st.selectbox("Select Junction", wn.junction_name_list)
elif component_type == "Tank":
    component_id = st.selectbox("Select Tank", wn.tank_name_list)
elif component_type == "Pump":
    component_id = st.selectbox("Select Pump", wn.pump_name_list)
else:
    component_id = st.selectbox("Select Valve", wn.valve_name_list)

attack_type = st.selectbox(
    "Attack Type",
    ["None", "False Data Injection (FDI)", "Denial of Service (DoS)"]
)

t_start = st.number_input("Attack start time (seconds)", 0, 86400, 3600)
attack_duration = st.number_input("Attack duration (seconds)", 0, 86400, 3600)
t_end = t_start + attack_duration

attack_magnitude = st.slider(
    "Attack Magnitude (%)",
    -80, 80, 40
)

# -------------------------------
# Baseline simulation
# -------------------------------
wn.options.time.duration = 24 * 3600
wn.options.time.hydraulic_timestep = 3600

baseline_sim = wntr.sim.EpanetSimulator(wn)
baseline_results = baseline_sim.run_sim()

# -------------------------------
# Attack simulation
# -------------------------------
wn_attack = wntr.network.WaterNetworkModel("model.inp")
wn_attack.options.time.duration = 24 * 3600
wn_attack.options.time.hydraulic_timestep = 3600

if attack_type == "False Data Injection (FDI)":
    if component_type in ["Junction", "Tank"]:
        node = wn_attack.get_node(component_id)
        node.base_demand *= (1 + attack_magnitude / 100)

elif attack_type == "Denial of Service (DoS)":
    if component_type in ["Pump", "Valve"]:
        link = wn_attack.get_link(component_id)
        control = wntr.network.controls.Control(
            wntr.network.controls.SimTimeCondition(
                wn_attack, "=", t_start
            ),
            wntr.network.controls.LinkStatusAction(
                link, 0  # CLOSED / OFF
            )
        )
        wn_attack.add_control(f"DoS_start_{component_id}", control)

        restore = wntr.network.controls.Control(
            wntr.network.controls.SimTimeCondition(
                wn_attack, "=", t_end
            ),
            wntr.network.controls.LinkStatusAction(
                link, 1  # OPEN / ON
            )
        )
        wn_attack.add_control(f"DoS_end_{component_id}", restore)

attack_sim = wntr.sim.EpanetSimulator(wn_attack)
attack_results = attack_sim.run_sim()

# -------------------------------
# Metric extraction (example: tank)
# -------------------------------
if component_type == "Tank":
    pre = get_tank_level(baseline_results, wn, component_id)
    during = get_tank_level(attack_results, wn_attack, component_id)

    df = pd.DataFrame({
        "Pre_Attack": pre,
        "During_Attack": during
    })

    # -------------------------------
    # IEEE-style plot
    # -------------------------------
    fig, ax = plt.subplots(figsize=(7,4))
    pre.plot(ax=ax, label="Pre-Attack")
    during.plot(ax=ax, label="During Attack", linestyle="--")
    ieee_plot_style(ax, "Time (s)", "Tank Level (m)",
                    f"Tank {component_id} Response")
    ax.legend()
    st.pyplot(fig)

    # -------------------------------
    # Export CSV
    # -------------------------------
    st.download_button(
        "Download IEEE-ready CSV",
        df.to_csv().encode(),
        f"{component_id}_{attack_type}.csv",
        "text/csv"
    )





