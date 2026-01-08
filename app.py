"""
EPANET Network Analysis with FDI/DOS Attack Simulation
PhD Research Application - Water Distribution Network Security
"""

import streamlit as st
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import networkx as nx
from io import StringIO
import base64
from datetime import datetime
import warnings
warnings.filterwarnings('ignore')

# Set page configuration
st.set_page_config(
    page_title="WDN Security Analysis Platform",
    page_icon="💧",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Import WNTR for EPANET functionality
try:
    import wntr
    from wntr.network import WaterNetworkModel
    WNTR_AVAILABLE = True
except ImportError:
    st.error("""
    WNTR (Water Network Tool for Resilience) is not installed.
    
    Please install it using: `pip install wntr`
    
    WNTR provides EPANET .inp file parsing and hydraulic simulation capabilities.
    """)
    WNTR_AVAILABLE = False

# IEEE Plot Style Configuration
plt.style.use('seaborn-v0_8-paper')
plt.rcParams.update({
    'font.family': 'serif',
    'font.serif': ['Times New Roman', 'Times'],
    'font.size': 10,
    'axes.titlesize': 11,
    'axes.labelsize': 10,
    'legend.fontsize': 9,
    'xtick.labelsize': 9,
    'ytick.labelsize': 9,
    'figure.dpi': 300,
    'savefig.dpi': 300,
    'savefig.bbox': 'tight',
    'savefig.pad_inches': 0.1,
    'figure.constrained_layout.use': True,
})

# Custom CSS for professional appearance
st.markdown("""
<style>
    .main-header {
        font-size: 2.5rem;
        color: #1E3A8A;
        font-weight: 700;
        margin-bottom: 1rem;
    }
    .sub-header {
        font-size: 1.5rem;
        color: #374151;
        font-weight: 600;
        margin-top: 1.5rem;
        margin-bottom: 1rem;
        border-bottom: 2px solid #E5E7EB;
        padding-bottom: 0.5rem;
    }
    .metric-card {
        background-color: #F9FAFB;
        border-radius: 0.5rem;
        padding: 1rem;
        border-left: 4px solid #3B82F6;
        margin-bottom: 1rem;
    }
    .attack-simulation {
        background-color: #FEF2F2;
        border-radius: 0.5rem;
        padding: 1.5rem;
        border: 1px solid #FCA5A5;
    }
    .stButton button {
        background-color: #1E40AF;
        color: white;
        font-weight: 600;
        border-radius: 0.375rem;
        padding: 0.5rem 1rem;
    }
    .stButton button:hover {
        background-color: #1E3A8A;
    }
</style>
""", unsafe_allow_html=True)

class WDNAnalyzer:
    """Main class for WDN analysis and attack simulation"""
    
    def __init__(self):
        self.wn = None
        self.results = None
        self.attack_results = None
        self.network_graph = None
        
    def load_inp_file(self, file_content):
        """Load EPANET .inp file"""
        try:
            self.wn = wntr.network.WaterNetworkModel(file_content)
            return True, "File loaded successfully"
        except Exception as e:
            return False, f"Error loading file: {str(e)}"
    
    def get_network_properties(self):
        """Extract network properties"""
        if not self.wn:
            return {}
        
        props = {
            'Number of Junctions': self.wn.num_junctions,
            'Number of Reservoirs': self.wn.num_reservoirs,
            'Number of Tanks': self.wn.num_tanks,
            'Number of Pipes': self.wn.num_pipes,
            'Number of Pumps': self.wn.num_pumps,
            'Number of Valves': self.wn.num_valves,
            'Simulation Duration (hr)': self.wn.options.time.duration / 3600,
            'Hydraulic Timestep (min)': self.wn.options.time.hydraulic_timestep / 60,
        }
        return props
    
    def simulate_hydraulics(self):
        """Run hydraulic simulation"""
        if not self.wn:
            return None
        
        sim = wntr.sim.EpanetSimulator(self.wn)
        self.results = sim.run_sim()
        return self.results
    
    def simulate_fdi_attack(self, target_nodes=None, attack_magnitude=0.3, attack_type='pressure'):
        """
        Simulate False Data Injection attack
        
        Parameters:
        -----------
        target_nodes: list of node IDs to attack
        attack_magnitude: magnitude of false data injection (0-1)
        attack_type: 'pressure' or 'flow'
        """
        if not self.results:
            st.warning("Please run baseline simulation first")
            return None
        
        attack_results = self.results.copy()
        
        if target_nodes is None:
            # Default to attacking 20% of nodes
            all_nodes = list(self.wn.node_name_list)
            n_attack = max(1, int(len(all_nodes) * 0.2))
            target_nodes = np.random.choice(all_nodes, n_attack, replace=False)
        
        if attack_type == 'pressure':
            for node in target_nodes:
                if node in attack_results.node['pressure'].columns:
                    # Add bias attack
                    bias = attack_magnitude * np.random.randn()
                    attack_results.node['pressure'][node] += bias
                    
                    # Add noise attack
                    noise_level = 0.1 * attack_magnitude
                    noise = noise_level * np.random.randn(len(attack_results.node['pressure']))
                    attack_results.node['pressure'][node] += noise
        
        elif attack_type == 'flow':
            for node in target_nodes:
                if node in attack_results.link['flowrate'].columns:
                    bias = attack_magnitude * np.random.randn()
                    attack_results.link['flowrate'][node] += bias
        
        self.attack_results = attack_results
        return attack_results
    
    def simulate_dos_attack(self, target_links=None, attack_duration=2):
        """
        Simulate Denial of Service attack (pipe closure)
        
        Parameters:
        -----------
        target_links: list of link IDs to attack (close)
        attack_duration: duration of attack in hours
        """
        if not self.wn:
            return None
        
        # Create a copy of the network for attack simulation
        wn_dos = self.wn.copy()
        
        if target_links is None:
            all_links = list(self.wn.link_name_list)
            n_attack = max(1, int(len(all_links) * 0.1))
            target_links = np.random.choice(all_links, n_attack, replace=False)
        
        # Close the target links
        for link in target_links:
            if link in wn_dos.link_name_list:
                wn_dos.get_link(link).status = 0  # Closed
        
        # Run simulation with DOS attack
        sim = wntr.sim.EpanetSimulator(wn_dos)
        dos_results = sim.run_sim()
        
        return dos_results, target_links
    
    def create_ieee_plot(self, data, title, xlabel, ylabel, filename):
        """Create IEEE style publication plot"""
        fig, ax = plt.subplots(figsize=(6, 4))
        
        if isinstance(data, pd.DataFrame):
            for column in data.columns:
                ax.plot(data.index / 3600, data[column], linewidth=1.5, alpha=0.8)
        elif isinstance(data, pd.Series):
            ax.plot(data.index / 3600, data.values, linewidth=1.5, color='#1E40AF')
        
        ax.set_xlabel(xlabel, fontweight='bold')
        ax.set_ylabel(ylabel, fontweight='bold')
        ax.set_title(title, fontsize=11, fontweight='bold')
        ax.grid(True, alpha=0.3)
        ax.legend(loc='best', frameon=True, fancybox=True, shadow=True)
        
        # IEEE style adjustments
        ax.spines['top'].set_visible(False)
        ax.spines['right'].set_visible(False)
        
        return fig
    
    def export_to_csv(self, dataframe, filename):
        """Export DataFrame to CSV with download link"""
        csv = dataframe.to_csv(index=True)
        b64 = base64.b64encode(csv.encode()).decode()
        href = f'<a href="data:file/csv;base64,{b64}" download="{filename}.csv">Download {filename} CSV</a>'
        return href

def main():
    """Main application function"""
    
    # Header
    st.markdown('<h1 class="main-header">💧 WDN Security Analysis Platform</h1>', unsafe_allow_html=True)
    st.markdown("""
    *PhD Research Application for EPANET Model Analysis with FDI/DOS Attack Simulation*
    """)
    
    if not WNTR_AVAILABLE:
        st.stop()
    
    # Initialize analyzer
    if 'analyzer' not in st.session_state:
        st.session_state.analyzer = WDNAnalyzer()
    
    analyzer = st.session_state.analyzer
    
    # Sidebar
    with st.sidebar:
        st.image("https://img.icons8.com/color/96/000000/water.png", width=100)
        st.markdown("### Navigation")
        
        app_mode = st.radio(
            "Select Mode:",
            ["📁 Upload & Overview", "📊 Network Visualization", "⚡ Attack Simulation", 
             "📈 Results Analysis", "💾 Export Results"]
        )
        
        st.markdown("---")
        st.markdown("### Settings")
        
        if analyzer.wn:
            st.info(f"Network Loaded: {analyzer.wn.name}")
        
        st.markdown("---")
        st.markdown("""
        **PhD Research Tool**  
        Developed for Water Distribution Network Security Analysis  
        Version 1.0
        """)
    
    # Main content based on selected mode
    if app_mode == "📁 Upload & Overview":
        render_upload_overview(analyzer)
    
    elif app_mode == "📊 Network Visualization":
        render_visualization(analyzer)
    
    elif app_mode == "⚡ Attack Simulation":
        render_attack_simulation(analyzer)
    
    elif app_mode == "📈 Results Analysis":
        render_results_analysis(analyzer)
    
    elif app_mode == "💾 Export Results":
        render_export_results(analyzer)

def render_upload_overview(analyzer):
    """Render upload and overview section"""
    st.markdown('<h2 class="sub-header">📁 Upload EPANET .INP File</h2>', unsafe_allow_html=True)
    
    col1, col2 = st.columns([2, 1])
    
    with col1:
        uploaded_file = st.file_uploader("Choose an EPANET .inp file", type="inp")
        
        if uploaded_file is not None:
            # Read file content
            stringio = StringIO(uploaded_file.getvalue().decode("utf-8"))
            file_content = stringio.read()
            
            # Load network
            success, message = analyzer.load_inp_file(file_content)
            
            if success:
                st.success(message)
                
                # Display network properties
                st.markdown('<h3 class="sub-header">Network Properties</h3>', unsafe_allow_html=True)
                
                properties = analyzer.get_network_properties()
                cols = st.columns(3)
                
                for idx, (key, value) in enumerate(properties.items()):
                    with cols[idx % 3]:
                        st.markdown(f"""
                        <div class="metric-card">
                            <div style="font-size: 0.9rem; color: #6B7280;">{key}</div>
                            <div style="font-size: 1.5rem; font-weight: 700; color: #1E40AF;">{value}</div>
                        </div>
                        """, unsafe_allow_html=True)
                
                # Run baseline simulation
                if st.button("🚀 Run Baseline Simulation", type="primary"):
                    with st.spinner("Running hydraulic simulation..."):
                        results = analyzer.simulate_hydraulics()
                        if results:
                            st.success("Baseline simulation completed successfully!")
                            st.session_state.baseline_completed = True
                
            else:
                st.error(message)
    
    with col2:
        st.markdown("### Sample Networks")
        st.markdown("""
        Don't have an .inp file? Try these examples:
        
        1. **Net3.inp** - Standard EPANET example
        2. **BWSN.inp** - Battle of Water Networks
        3. **Richmond.inp** - Medium-sized network
        
        *Download from [EPANET Website](https://epanet.es)*
        """)
        
        st.markdown("### Requirements")
        st.markdown("""
        - EPANET .inp format
        - Complete network definition
        - Proper node and link IDs
        - Control rules (optional)
        """)

def render_visualization(analyzer):
    """Render network visualization section"""
    st.markdown('<h2 class="sub-header">📊 Network Visualization</h2>', unsafe_allow_html=True)
    
    if not analyzer.wn:
        st.warning("Please upload an EPANET .inp file first")
        return
    
    col1, col2 = st.columns([3, 1])
    
    with col1:
        # Network plot
        st.markdown("### Network Topology")
        
        plot_type = st.selectbox(
            "Select visualization type:",
            ["Basic Network", "Pressure Distribution", "Flow Distribution", "Elevation Profile"]
        )
        
        # Create network graph
        try:
            fig, ax = plt.subplots(figsize=(10, 8))
            
            if plot_type == "Basic Network":
                # Simple network plot
                G = analyzer.wn.get_graph()
                pos = {node: (analyzer.wn.get_node(node).coordinates[0], 
                             analyzer.wn.get_node(node).coordinates[1]) 
                      for node in G.nodes()}
                
                nx.draw(G, pos, ax=ax, node_size=50, node_color='blue', 
                       edge_color='gray', width=2, with_labels=True, 
                       font_size=8)
                ax.set_title("Water Distribution Network Topology", fontweight='bold')
            
            elif plot_type == "Pressure Distribution" and analyzer.results:
                # Pressure contour
                pressure = analyzer.results.node['pressure'].iloc[-1]
                G = analyzer.wn.get_graph()
                
                node_colors = []
                for node in G.nodes():
                    if node in pressure:
                        node_colors.append(pressure[node])
                    else:
                        node_colors.append(0)
                
                pos = {node: (analyzer.wn.get_node(node).coordinates[0], 
                             analyzer.wn.get_node(node).coordinates[1]) 
                      for node in G.nodes()}
                
                nodes = nx.draw_networkx_nodes(G, pos, node_color=node_colors, 
                                              node_size=100, cmap=plt.cm.viridis, 
                                              ax=ax)
                edges = nx.draw_networkx_edges(G, pos, width=1, alpha=0.5, ax=ax)
                
                plt.colorbar(nodes, label='Pressure (m)', ax=ax)
                ax.set_title("Pressure Distribution at Final Time Step", fontweight='bold')
            
            ax.set_aspect('equal')
            st.pyplot(fig)
            
        except Exception as e:
            st.error(f"Error generating visualization: {str(e)}")
            # Fallback to simple plot
            st.info("Using simplified network representation")
            G = analyzer.wn.get_graph()
            fig, ax = plt.subplots(figsize=(10, 8))
            nx.draw(G, ax=ax, node_size=30, with_labels=False)
            st.pyplot(fig)
    
    with col2:
        st.markdown("### Visualization Settings")
        
        # Node selection
        if analyzer.wn:
            nodes = analyzer.wn.node_name_list
            selected_nodes = st.multiselect(
                "Highlight nodes:",
                nodes,
                default=nodes[:min(5, len(nodes))]
            )
            
            # Link selection
            links = analyzer.wn.link_name_list
            selected_links = st.multiselect(
                "Highlight links:",
                links,
                default=links[:min(5, len(links))]
            )
        
        # Plot customization
        st.markdown("#### Customization")
        node_size = st.slider("Node size", 10, 200, 50)
        line_width = st.slider("Line width", 0.5, 5.0, 2.0)
        
        if st.button("🔄 Refresh Visualization"):
            st.rerun()

def render_attack_simulation(analyzer):
    """Render attack simulation section"""
    st.markdown('<h2 class="sub-header">⚡ Attack Simulation</h2>', unsafe_allow_html=True)
    
    if not analyzer.wn:
        st.warning("Please upload an EPANET .inp file and run baseline simulation first")
        return
    
    if not hasattr(st.session_state, 'baseline_completed'):
        st.warning("Please run baseline simulation first")
        return
    
    tab1, tab2 = st.tabs(["🔓 False Data Injection (FDI)", "🚫 Denial of Service (DoS)"])
    
    with tab1:
        st.markdown("""
        <div class="attack-simulation">
        <h3>False Data Injection Attack</h3>
        <p>Simulate sensor data manipulation by injecting false measurements.</p>
        </div>
        """, unsafe_allow_html=True)
        
        col1, col2 = st.columns(2)
        
        with col1:
            # Attack parameters
            st.markdown("#### Attack Parameters")
            
            attack_type = st.selectbox(
                "Attack type:",
                ["Pressure Manipulation", "Flow Manipulation", "Demand Manipulation"]
            )
            
            attack_magnitude = st.slider(
                "Attack magnitude (%):",
                0, 100, 30,
                help="Percentage of deviation from actual values"
            )
            
            attack_duration = st.slider(
                "Attack duration (hours):",
                1, 24, 6
            )
        
        with col2:
            # Target selection
            st.markdown("#### Target Selection")
            
            target_nodes = st.multiselect(
                "Select nodes to attack:",
                analyzer.wn.node_name_list,
                help="Select specific nodes for targeted attack"
            )
            
            if not target_nodes:
                st.info("No nodes selected. Random nodes will be attacked.")
                n_random = st.slider("Number of random nodes:", 1, 20, 5)
                target_nodes = None
        
        # Run FDI attack
        if st.button("🚨 Simulate FDI Attack", type="primary"):
            with st.spinner("Simulating FDI attack..."):
                # Convert attack parameters
                magnitude = attack_magnitude / 100.0
                
                if attack_type == "Pressure Manipulation":
                    attack_results = analyzer.simulate_fdi_attack(
                        target_nodes=target_nodes,
                        attack_magnitude=magnitude,
                        attack_type='pressure'
                    )
                elif attack_type == "Flow Manipulation":
                    attack_results = analyzer.simulate_fdi_attack(
                        target_nodes=target_nodes,
                        attack_magnitude=magnitude,
                        attack_type='flow'
                    )
                
                if attack_results is not None:
                    st.session_state.fdi_results = attack_results
                    st.session_state.fdi_params = {
                        'type': attack_type,
                        'magnitude': attack_magnitude,
                        'duration': attack_duration,
                        'targets': target_nodes
                    }
                    st.success("FDI attack simulation completed!")
                    
                    # Show impact metrics
                    if analyzer.results and hasattr(st.session_state, 'fdi_results'):
                        baseline_pressure = analyzer.results.node['pressure'].mean().mean()
                        attack_pressure = st.session_state.fdi_results.node['pressure'].mean().mean()
                        impact = abs((attack_pressure - baseline_pressure) / baseline_pressure * 100)
                        
                        st.metric(
                            label="Pressure Impact",
                            value=f"{impact:.2f}%",
                            delta=f"{attack_pressure - baseline_pressure:.2f} m"
                        )
    
    with tab2:
        st.markdown("""
        <div class="attack-simulation">
        <h3>Denial of Service Attack</h3>
        <p>Simulate physical or cyber attacks that disable network components.</p>
        </div>
        """, unsafe_allow_html=True)
        
        col1, col2 = st.columns(2)
        
        with col1:
            st.markdown("#### Attack Parameters")
            
            dos_type = st.selectbox(
                "DoS type:",
                ["Pipe Closure", "Pump Failure", "Valve Manipulation", "Tank Isolation"]
            )
            
            attack_severity = st.slider(
                "Attack severity:",
                1, 10, 5,
                help="Severity level (1=low, 10=critical)"
            )
            
            recovery_time = st.slider(
                "Recovery time (hours):",
                1, 72, 24
            )
        
        with col2:
            st.markdown("#### Target Selection")
            
            target_links = st.multiselect(
                "Select links to disable:",
                analyzer.wn.link_name_list,
                help="Select specific links to simulate closure"
            )
            
            if not target_links and dos_type == "Pipe Closure":
                n_random = st.slider("Number of random pipes:", 1, 10, 3)
                target_links = None
        
        # Run DoS attack
        if st.button("🚨 Simulate DoS Attack", type="primary"):
            with st.spinner("Simulating DoS attack..."):
                dos_results, attacked_links = analyzer.simulate_dos_attack(
                    target_links=target_links,
                    attack_duration=recovery_time
                )
                
                if dos_results is not None:
                    st.session_state.dos_results = dos_results
                    st.session_state.dos_attacked_links = attacked_links
                    st.session_state.dos_params = {
                        'type': dos_type,
                        'severity': attack_severity,
                        'recovery': recovery_time
                    }
                    st.success(f"DoS attack simulation completed! {len(attacked_links)} links disabled.")
                    
                    # Show impact
                    if analyzer.results:
                        baseline_flow = analyzer.results.link['flowrate'].abs().mean().mean()
                        dos_flow = dos_results.link['flowrate'].abs().mean().mean()
                        flow_reduction = ((baseline_flow - dos_flow) / baseline_flow * 100)
                        
                        col1, col2, col3 = st.columns(3)
                        with col1:
                            st.metric(
                                label="Flow Reduction",
                                value=f"{flow_reduction:.1f}%",
                                delta="Negative impact"
                            )
                        with col2:
                            st.metric(
                                label="Links Affected",
                                value=len(attacked_links)
                            )
                        with col3:
                            affected_nodes = set()
                            for link in attacked_links:
                                link_obj = analyzer.wn.get_link(link)
                                affected_nodes.update([link_obj.start_node, link_obj.end_node])
                            st.metric(
                                label="Nodes Affected",
                                value=len(affected_nodes)
                            )

def render_results_analysis(analyzer):
    """Render results analysis section"""
    st.markdown('<h2 class="sub-header">📈 Results Analysis</h2>', unsafe_allow_html=True)
    
    if not analyzer.results:
        st.warning("Please run baseline simulation first")
        return
    
    tab1, tab2, tab3 = st.tabs(["📊 Baseline Results", "⚡ Attack Comparison", "📉 Impact Metrics"])
    
    with tab1:
        st.markdown("### Baseline Simulation Results")
        
        # Select results to display
        result_type = st.selectbox(
            "Select result type:",
            ["Node Pressure", "Link Flow", "Node Demand", "Link Velocity"]
        )
        
        if result_type == "Node Pressure":
            data = analyzer.results.node['pressure']
            ylabel = "Pressure (m)"
        elif result_type == "Link Flow":
            data = analyzer.results.link['flowrate']
            ylabel = "Flow Rate (m³/s)"
        elif result_type == "Node Demand":
            data = analyzer.results.node['demand']
            ylabel = "Demand (L/s)"
        
        # Select specific elements to plot
        elements = st.multiselect(
            "Select elements to display:",
            data.columns.tolist(),
            default=data.columns.tolist()[:min(5, len(data.columns))]
        )
        
        if elements:
            # Create IEEE style plot
            fig = analyzer.create_ieee_plot(
                data[elements],
                title=f"Baseline {result_type}",
                xlabel="Time (hours)",
                ylabel=ylabel,
                filename=f"baseline_{result_type.replace(' ', '_').lower()}"
            )
            st.pyplot(fig)
            
            # Statistics
            st.markdown("#### Statistical Summary")
            stats_df = data[elements].describe()
            st.dataframe(stats_df, use_container_width=True)
    
    with tab2:
        st.markdown("### Attack vs Baseline Comparison")
        
        if not (hasattr(st.session_state, 'fdi_results') or hasattr(st.session_state, 'dos_results')):
            st.info("No attack results available. Please run attack simulations first.")
        else:
            # Select attack type for comparison
            attack_to_compare = st.selectbox(
                "Select attack for comparison:",
                ["FDI Attack", "DoS Attack", "Both Attacks"]
            )
            
            # Comparison plot
            compare_element = st.selectbox(
                "Select element for comparison:",
                analyzer.wn.node_name_list[:10] if analyzer.wn else []
            )
            
            if compare_element and analyzer.results:
                fig, ax = plt.subplots(figsize=(8, 5))
                
                # Plot baseline
                if compare_element in analyzer.results.node['pressure'].columns:
                    baseline = analyzer.results.node['pressure'][compare_element]
                    ax.plot(baseline.index / 3600, baseline.values, 
                           label='Baseline', linewidth=2, color='#1E40AF')
                
                # Plot FDI attack
                if (attack_to_compare in ["FDI Attack", "Both Attacks"] and 
                    hasattr(st.session_state, 'fdi_results') and
                    compare_element in st.session_state.fdi_results.node['pressure'].columns):
                    fdi_data = st.session_state.fdi_results.node['pressure'][compare_element]
                    ax.plot(fdi_data.index / 3600, fdi_data.values, 
                           label='FDI Attack', linewidth=2, color='#DC2626', linestyle='--')
                
                # Plot DoS attack
                if (attack_to_compare in ["DoS Attack", "Both Attacks"] and 
                    hasattr(st.session_state, 'dos_results') and
                    compare_element in st.session_state.dos_results.node['pressure'].columns):
                    dos_data = st.session_state.dos_results.node['pressure'][compare_element]
                    ax.plot(dos_data.index / 3600, dos_data.values, 
                           label='DoS Attack', linewidth=2, color='#059669', linestyle='-.')
                
                ax.set_xlabel("Time (hours)", fontweight='bold')
                ax.set_ylabel("Pressure (m)", fontweight='bold')
                ax.set_title(f"Comparison for Node {compare_element}", fontweight='bold')
                ax.legend()
                ax.grid(True, alpha=0.3)
                
                st.pyplot(fig)
    
    with tab3:
        st.markdown("### Attack Impact Metrics")
        
        if not (hasattr(st.session_state, 'fdi_results') or hasattr(st.session_state, 'dos_results')):
            st.info("No attack results to analyze")
        else:
            # Calculate impact metrics
            impact_metrics = {}
            
            if hasattr(st.session_state, 'fdi_results'):
                # FDI impact metrics
                baseline_pressure = analyzer.results.node['pressure']
                fdi_pressure = st.session_state.fdi_results.node['pressure']
                
                pressure_diff = (fdi_pressure - baseline_pressure).abs()
                impact_metrics['FDI'] = {
                    'Max Pressure Deviation (m)': pressure_diff.max().max(),
                    'Mean Pressure Deviation (m)': pressure_diff.mean().mean(),
                    'Nodes Above Threshold': (pressure_diff.max() > 5).sum(),
                    'Time Above Threshold (hrs)': (pressure_diff.max(axis=1) > 5).sum() / 4
                }
            
            if hasattr(st.session_state, 'dos_results'):
                # DoS impact metrics
                baseline_flow = analyzer.results.link['flowrate'].abs()
                dos_flow = st.session_state.dos_results.link['flowrate'].abs()
                
                flow_reduction = ((baseline_flow - dos_flow) / baseline_flow.replace(0, 1e-6) * 100)
                impact_metrics['DoS'] = {
                    'Max Flow Reduction (%)': flow_reduction.max().max(),
                    'Mean Flow Reduction (%)': flow_reduction.mean().mean(),
                    'Links with >50% Reduction': (flow_reduction.max() > 50).sum(),
                    'Network Serviceability Index': 100 - flow_reduction.mean().mean()
                }
            
            # Display metrics
            for attack_type, metrics in impact_metrics.items():
                st.markdown(f"#### {attack_type} Impact Metrics")
                cols = st.columns(len(metrics))
                
                for idx, (metric_name, value) in enumerate(metrics.items()):
                    with cols[idx % len(cols)]:
                        st.metric(label=metric_name, value=f"{value:.2f}")

def render_export_results(analyzer):
    """Render export results section"""
    st.markdown('<h2 class="sub-header">💾 Export Results</h2>', unsafe_allow_html=True)
    
    if not analyzer.results:
        st.warning("No simulation results to export")
        return
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.markdown("### Export Data")
        
        # Export options
        export_format = st.selectbox(
            "Select export format:",
            ["CSV", "Excel", "JSON", "Pickle"]
        )
        
        data_to_export = st.multiselect(
            "Select data to export:",
            ["Baseline Results", "FDI Attack Results", "DoS Attack Results", 
             "Network Properties", "Attack Parameters", "Impact Metrics"],
            default=["Baseline Results"]
        )
        
        filename = st.text_input(
            "Filename prefix:",
            value=f"wdn_analysis_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        )
    
    with col2:
        st.markdown("### Export Settings")
        
        include_metadata = st.checkbox("Include metadata", value=True)
        compress_data = st.checkbox("Compress data", value=False)
        split_by_type = st.checkbox("Split files by data type", value=True)
        
        resolution = st.slider(
            "Plot resolution (DPI):",
            100, 600, 300
        )
        
        plt.rcParams['savefig.dpi'] = resolution
    
    # Export button
    if st.button("📥 Export All Data", type="primary"):
        with st.spinner("Preparing export..."):
            export_data = {}
            
            if "Baseline Results" in data_to_export and analyzer.results:
                export_data['baseline_pressure'] = analyzer.results.node['pressure']
                export_data['baseline_flow'] = analyzer.results.link['flowrate']
                export_data['baseline_demand'] = analyzer.results.node['demand']
            
            if "FDI Attack Results" in data_to_export and hasattr(st.session_state, 'fdi_results'):
                export_data['fdi_pressure'] = st.session_state.fdi_results.node['pressure']
            
            if "DoS Attack Results" in data_to_export and hasattr(st.session_state, 'dos_results'):
                export_data['dos_pressure'] = st.session_state.dos_results.node['pressure']
                export_data['dos_flow'] = st.session_state.dos_results.link['flowrate']
            
            if "Network Properties" in data_to_export and analyzer.wn:
                export_data['network_properties'] = pd.DataFrame([analyzer.get_network_properties()])
            
            if "Attack Parameters" in data_to_export:
                attack_params = {}
                if hasattr(st.session_state, 'fdi_params'):
                    attack_params['fdi'] = st.session_state.fdi_params
                if hasattr(st.session_state, 'dos_params'):
                    attack_params['dos'] = st.session_state.dos_params
                if attack_params:
                    export_data['attack_parameters'] = pd.json_normalize(attack_params)
            
            # Create plots for export
            if analyzer.results:
                st.markdown("### Generated Plots")
                
                # Create and display sample plots
                fig1 = analyzer.create_ieee_plot(
                    analyzer.results.node['pressure'].iloc[:, :3],
                    title="Sample Pressure Plot",
                    xlabel="Time (hours)",
                    ylabel="Pressure (m)",
                    filename="sample_pressure"
                )
                
                col1, col2 = st.columns(2)
                with col1:
                    st.pyplot(fig1)
                    st.download_button(
                        label="Download Pressure Plot",
                        data=fig_to_bytes(fig1),
                        file_name=f"{filename}_pressure_plot.png",
                        mime="image/png"
                    )
                
                # Create download links for data
                st.markdown("### Download Data Files")
                
                for data_name, data in export_data.items():
                    if isinstance(data, pd.DataFrame):
                        csv = data.to_csv()
                        b64 = base64.b64encode(csv.encode()).decode()
                        download_link = f'<a href="data:file/csv;base64,{b64}" download="{filename}_{data_name}.csv">Download {data_name}.csv</a>'
                        st.markdown(download_link, unsafe_allow_html=True)
            
            st.success("Export completed successfully!")

def fig_to_bytes(fig):
    """Convert matplotlib figure to bytes for download"""
    import io
    buf = io.BytesIO()
    fig.savefig(buf, format='png', dpi=300, bbox_inches='tight')
    buf.seek(0)
    return buf

if __name__ == "__main__":
    main()







