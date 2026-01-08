import streamlit as st
import wntr
import pandas as pd
import matplotlib.pyplot as plt
import tempfile

st.set_page_config(layout="wide")
st.title("WDN CPS Security Experiment Tool")

uploaded_file = st.file_uploader("Upload EPANET .inp file", type=["inp"])

if uploaded_file:
    with open("model.inp", "wb") as f:
        f.write(uploaded_file.getbuffer())

    wn = wntr.network.WaterNetworkModel("model.inp")

    # -------------------------------
    # USER SELECTION
    # -------------------------------
    tank_id = st.selectbox("Select Tank", wn.tank_name_list)

    attack_type = st.selectbox(
        "Attack Type",
        ["None", "False Data Injection (FDI)", "Denial of Service (DoS)"]
    )

    attack_start = st.number_input("Attack start time (hr)", 0.0)
    attack_end = st.number_input("Attack end time (hr)", 24.0)

    fdi_bias = st.slider("FDI Bias (%)", -50, 50, 20)

    # -------------------------------
    # BASELINE SIMULATION
    # -------------------------------
    st.subheader("Running Baseline Simulation")
    sim = wntr.sim.EpanetSimulator(wn)
    baseline = sim.run_sim()

    baseline_level = baseline.node["pressure"].loc[:, tank_id]

    # -------------------------------
    # ATTACK SIMULATION
    # -------------------------------
    wn_attack = wntr.network.WaterNetworkModel("model.inp")

    if attack_type == "False Data Injection (FDI)":
        wn_attack.options.time.hydraulic_timestep = 3600
        wn_attack.options.time.duration = 24 * 3600

        # emulate FDI by altering demand
        demand_multiplier = 1 + fdi_bias / 100
        wn_attack.get_node(tank_id).base_demand *= demand_multiplier

    elif attack_type == "Denial of Service (DoS)":
        wn_attack.get_node(tank_id).base_demand = 0.0

    sim_attack = wntr.sim.EpanetSimulator(wn_attack)
    attack = sim_attack.run_sim()

    attack_level = attack.node["pressure"].loc[:, tank_id]

    # -------------------------------
    # PLOTTING
    # -------------------------------
    st.subheader("Pre vs Post Attack Comparison")

    fig, ax = plt.subplots()
    baseline_level.plot(ax=ax, label="Baseline")
    attack_level.plot(ax=ax, label="Post-Attack", linestyle="--")
    ax.set_xlabel("Time (hours)")
    ax.set_ylabel("Pressure")
    ax.legend()
    ax.grid(True)

    st.pyplot(fig)

    # -------------------------------
    # EXPORT
    # -------------------------------
    df = pd.DataFrame({
        "baseline": baseline_level,
        "attack": attack_level
    })

    st.download_button(
        "Download CSV",
        df.to_csv().encode(),
        "results.csv",
        "text/csv"
    )

