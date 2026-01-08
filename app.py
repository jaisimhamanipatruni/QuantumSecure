import streamlit as st
import wntr
import pandas as pd
import matplotlib.pyplot as plt

st.set_page_config(layout="wide")
st.title("WDN CPS Security Experiment Tool")

# -------------------------------
# Upload EPANET model
# -------------------------------
uploaded_file = st.file_uploader("Upload EPANET .inp file", type=["inp"])

if uploaded_file:
    with open("model.inp", "wb") as f:
        f.write(uploaded_file.getbuffer())

    wn = wntr.network.WaterNetworkModel("model.inp")

    st.success("EPANET model loaded successfully")

    # -------------------------------
    # USER SELECTION
    # -------------------------------
    st.subheader("Experiment Configuration")

    node_id = st.selectbox(
        "Select node (Tank or Junction)",
        wn.node_name_list
    )

    attack_type = st.selectbox(
        "Attack Type",
        ["None", "False Data Injection (FDI)", "Denial of Service (DoS)"]
    )

    fdi_bias = st.slider(
        "FDI Bias (%)",
        min_value=-50,
        max_value=50,
        value=20
    )

    # -------------------------------
    # BASELINE SIMULATION
    # -------------------------------
    st.subheader("Running Baseline Simulation")

    sim = wntr.sim.EpanetSimulator(wn)
    baseline_results = sim.run_sim()

    node = wn.get_node(node_id)

    if node.node_type == "Tank":
        baseline_series = baseline_results.node["level"].loc[:, node_id]
        ylabel = "Tank Level"
    else:
        baseline_series = baseline_results.node["pressure"].loc[:, node_id]
        ylabel = "Pressure"

    # -------------------------------
    # ATTACK SIMULATION
    # -------------------------------
    wn_attack = wntr.network.WaterNetworkModel("model.inp")

    if attack_type == "False Data Injection (FDI)":
        if node.node_type != "Tank":
            st.warning("FDI demo implemented on tanks only (for clarity).")
        else:
            multiplier = 1 + fdi_bias / 100
            wn_attack.get_node(node_id).base_demand *= multiplier

    elif attack_type == "Denial of Service (DoS)":
        wn_attack.get_node(node_id).base_demand = 0.0

    sim_attack = wntr.sim.EpanetSimulator(wn_attack)
    attack_results = sim_attack.run_sim()

    if node.node_type == "Tank":
        attack_series = attack_results.node["level"].loc[:, node_id]
    else:
        attack_series = attack_results.node["pressure"].loc[:, node_id]

    # -------------------------------
    # PLOTTING
    # -------------------------------
    st.subheader("Pre vs Post Attack Comparison")

    fig, ax = plt.subplots(figsize=(7, 4))
    baseline_series.plot(ax=ax, label="Baseline", linewidth=2)
    attack_series.plot(ax=ax, label="Post-Attack", linestyle="--")

    ax.set_xlabel("Time")
    ax.set_ylabel(ylabel)
    ax.legend()
    ax.grid(True)

    st.pyplot(fig)

    # -------------------------------
    # EXPORT RESULTS
    # -------------------------------
    results_df = pd.DataFrame({
        "Baseline": baseline_series,
        "Post_Attack": attack_series
    })

    st.download_button(
        label="Download Results (CSV)",
        data=results_df.to_csv().encode(),
        file_name=f"{node_id}_{attack_type.replace(' ', '_')}.csv",
        mime="text/csv"
    )

else:
    st.info("Please upload an EPANET .inp file to begin.")


