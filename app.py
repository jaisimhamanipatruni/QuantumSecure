"""
EPANET Network Analysis with FDI/DOS Attack Simulation
PhD Research Application - Water Distribution Network Security
"""

import streamlit as st
import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import networkx as nx
from io import StringIO, BytesIO
import base64
import tempfile
import os
import copy
import json
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
    .info-box {
        background-color: #EFF6FF;
        border-radius: 0.5rem;
        padding: 1rem;
        margin: 1rem 0;
        border-left: 4px solid #3B82F6;
    }
    .warning-box {
        background-color: #FEF3C7;
        border-radius: 0.5rem;
        padding: 1rem;
        margin: 1rem 0;
        border-left: 4px solid #F59E0B;
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
        self.temp_file_path = None
        
    def load_inp_file(self, uploaded_file):
        """Load EPANET .inp file from uploaded file"""
        try:
            # Save uploaded file to a temporary location
            with tempfile.NamedTemporaryFile(mode='w', suffix='.inp', delete=False) as tmp_file:
                # Read the uploaded file content
                content = uploaded_file.getvalue().decode("utf-8")
                tmp_file.write(content)
                self.temp_file_path = tmp_file.name
            
            # Load the network from the temporary file
            self.wn = WaterNetworkModel(self.temp_file_path)
            
            # Clean up the temporary file
            os.unlink(self.temp_file_path)
            self.temp_file_path = None
            
            return True, "File loaded successfully"
        except Exception as e:
            # Clean up if there was an error
            if self.temp_file_path and os.path.exists(self.temp_file_path):
                os.unlink(self.temp_file_path)
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
        
        try:
            sim = wntr.sim.EpanetSimulator(self.wn)
            self.results = sim.run_sim()
            return self.results
        except Exception as e:
            st.error(f"Simulation error: {str(e)}")
            return None
    
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
            return None
        
        try:
            # Create a copy of results by running simulation again and then modifying
            # First, let's create a simple attack by modifying the results directly
            attack_results = type(self.results)()
            
            # Copy node results with manual copy of dataframes
            if hasattr(self.results.node, 'pressure'):
                attack_results.node['pressure'] = self.results.node['pressure'].copy(deep=True)
            
            if hasattr(self.results.node, 'demand'):
                attack_results.node['demand'] = self.results.node['demand'].copy(deep=True)
            
            if hasattr(self.results.node, 'head'):
                attack_results.node['head'] = self.results.node['head'].copy(deep=True)
            
            # Copy link results
            if hasattr(self.results.link, 'flowrate'):
                attack_results.link['flowrate'] = self.results.link['flowrate'].copy(deep=True)
            
            if hasattr(self.results.link, 'velocity'):
                attack_results.link['velocity'] = self.results.link['velocity'].copy(deep=True)
            
            if target_nodes is None:
                # Default to attacking 20% of nodes
                all_nodes = list(self.wn.node_name_list)
                n_attack = max(1, int(len(all_nodes) * 0.2))
                target_nodes = np.random.choice(all_nodes, n_attack, replace=False)
            
            if attack_type == 'pressure':
                for node in target_nodes:
                    if node in attack_results.node['pressure'].columns:
                        # Get the baseline pressure data
                        baseline_pressure = self.results.node['pressure'][node]
                        
                        # Calculate attack magnitude relative to baseline
                        std_dev = baseline_pressure.std()
                        if std_dev == 0:
                            std_dev = 1.0
                        
                        # Add bias attack (scaled by attack_magnitude)
                        bias = attack_magnitude * std_dev * np.random.randn()
                        
                        # Add noise attack
                        noise_level = 0.1 * attack_magnitude * std_dev
                        noise = noise_level * np.random.randn(len(attack_results.node['pressure']))
                        
                        # Apply attack
                        attack_results.node['pressure'][node] = baseline_pressure + bias + noise
            
            elif attack_type == 'flow':
                for node in target_nodes:
                    # For flow attacks, we need to check if node is a link
                    if node in self.wn.link_name_list and node in attack_results.link['flowrate'].columns:
                        baseline_flow = self.results.link['flowrate'][node]
                        std_dev = baseline_flow.std()
                        if std_dev == 0:
                            std_dev = 1.0
                        
                        bias = attack_magnitude * std_dev * np.random.randn()
                        attack_results.link['flowrate'][node] = baseline_flow + bias
            
            self.attack_results = attack_results
            return attack_results
            
        except Exception as e:
            st.error(f"FDI attack simulation error: {str(e)}")
            import traceback
            st.error(traceback.format_exc())
            return None
    
    def simulate_dos_attack(self, target_links=None, attack_duration=2):
        """
        Simulate Denial of Service attack (pipe closure)
        
        Parameters:
        -----------
        target_links: list of link IDs to attack (close)
        attack_duration: duration of attack in hours
        """
        if not self.wn:
            return None, []
        
        try:
            # Create a new temporary file for the modified network
            temp_dir = tempfile.gettempdir()
            temp_inp = os.path.join(temp_dir, f"dos_attack_{datetime.now().strftime('%Y%m%d_%H%M%S')}.inp")
            
            # Write the current network to a file
            self.wn.write_inpfile(temp_inp)
            
            # Load it back to create a copy
            wn_dos = WaterNetworkModel(temp_inp)
            
            if target_links is None:
                # Default to attacking 10% of pipes
                pipes = [link for link in wn_dos.link_name_list if wn_dos.get_link(link).link_type == 'Pipe']
                n_attack = max(1, int(len(pipes) * 0.1))
                target_links = np.random.choice(pipes, n_attack, replace=False)
            
            # Close the target links by setting status to 0 (closed)
            attacked_links = []
            for link_id in target_links:
                if link_id in wn_dos.link_name_list:
                    link = wn_dos.get_link(link_id)
                    link.status = 0  # Closed
                    attacked_links.append(link_id)
            
            # Run simulation with DOS attack
            sim = wntr.sim.EpanetSimulator(wn_dos)
            dos_results = sim.run_sim()
            
            # Clean up temp file
            if os.path.exists(temp_inp):
                os.remove(temp_inp)
            
            return dos_results, attacked_links
            
        except Exception as e:
            st.error(f"DoS attack simulation error: {str(e)}")
            import traceback
            st.error(traceback.format_exc())
            return None, []
    
    def create_network_plot(self, plot_type="Basic Network"):
        """Create network visualization plot"""
        try:
            if not self.wn:
                return None
                
            fig, ax = plt.subplots(figsize=(10, 8))
            
            if plot_type == "Basic Network":
                # Try to get coordinates if available
                pos = {}
                has_coordinates = True
                
                for node_name in self.wn.node_name_list:
                    node = self.wn.get_node(node_name)
                    if hasattr(node, 'coordinates') and node.coordinates is not None:
                        if len(node.coordinates) >= 2:
                            pos[node_name] = (node.coordinates[0], node.coordinates[1])
                        else:
                            has_coordinates = False
                            break
                    else:
                        has_coordinates = False
                        break
                
                if not has_coordinates or not pos:
                    # Generate layout using networkx
                    G = self.wn.get_graph()
                    pos = nx.spring_layout(G, seed=42)
                else:
                    G = self.wn.get_graph()
                
                # Color nodes by type
                node_colors = []
                node_shapes = []
                for node in G.nodes():
                    node_obj = self.wn.get_node(node)
                    node_type = getattr(node_obj, 'node_type', 'Junction')
                    if 'JUNCTION' in str(node_type).upper():
                        node_colors.append('blue')
                        node_shapes.append('o')
                    elif 'RESERVOIR' in str(node_type).upper():
                        node_colors.append('green')
                        node_shapes.append('s')
                    elif 'TANK' in str(node_type).upper():
                        node_colors.append('orange')
                        node_shapes.append('^')
                    else:
                        node_colors.append('gray')
                        node_shapes.append('o')
                
                # Draw nodes with different shapes
                for i, (node, shape) in enumerate(zip(G.nodes(), node_shapes)):
                    nx.draw_networkx_nodes(G, pos, nodelist=[node], 
                                          node_color=[node_colors[i]], 
                                          node_shape=shape, node_size=100, ax=ax)
                
                # Draw edges
                nx.draw_networkx_edges(G, pos, width=1.5, alpha=0.7, ax=ax)
                
                # Add labels for important nodes
                labels = {}
                for node in list(G.nodes())[:10]:  # Label first 10 nodes
                    labels[node] = node
                nx.draw_networkx_labels(G, pos, labels, font_size=8, ax=ax)
                
                ax.set_title("Water Distribution Network Topology", fontweight='bold')
                ax.axis('off')
                
                # Add legend
                from matplotlib.patches import Patch
                legend_elements = [
                    Patch(facecolor='blue', edgecolor='black', label='Junction'),
                    Patch(facecolor='green', edgecolor='black', label='Reservoir'),
                    Patch(facecolor='orange', edgecolor='black', label='Tank')
                ]
                ax.legend(handles=legend_elements, loc='upper right')
            
            elif plot_type == "Pressure Distribution" and self.results is not None:
                if hasattr(self.results.node, 'pressure'):
                    # Get pressure at last time step
                    pressure = self.results.node['pressure'].iloc[-1]
                    
                    # Get coordinates
                    pos = {}
                    has_coordinates = True
                    
                    for node_name in self.wn.node_name_list:
                        node = self.wn.get_node(node_name)
                        if hasattr(node, 'coordinates') and node.coordinates is not None:
                            if len(node.coordinates) >= 2:
                                pos[node_name] = (node.coordinates[0], node.coordinates[1])
                            else:
                                has_coordinates = False
                                break
                        else:
                            has_coordinates = False
                            break
                    
                    if not has_coordinates or not pos:
                        G = self.wn.get_graph()
                        pos = nx.spring_layout(G, seed=42)
                    else:
                        G = self.wn.get_graph()
                    
                    # Map pressure to colors
                    node_values = []
                    for node in G.nodes():
                        if node in pressure.index:
                            node_values.append(pressure[node])
                        else:
                            node_values.append(0)
                    
                    # Normalize for colormap
                    if node_values:
                        vmin = min(node_values)
                        vmax = max(node_values)
                        if vmin == vmax:
                            vmin = vmin - 1
                            vmax = vmax + 1
                    else:
                        vmin = 0
                        vmax = 1
                    
                    nodes = nx.draw_networkx_nodes(G, pos, node_color=node_values, 
                                                  node_size=100, cmap=plt.cm.viridis,
                                                  vmin=vmin, vmax=vmax, ax=ax)
                    nx.draw_networkx_edges(G, pos, width=1, alpha=0.5, ax=ax)
                    
                    # Add colorbar
                    cbar = plt.colorbar(nodes, ax=ax)
                    cbar.set_label('Pressure (m)', fontweight='bold')
                    ax.set_title("Pressure Distribution at Final Time Step", fontweight='bold')
                    ax.axis('off')
            
            return fig
            
        except Exception as e:
            st.error(f"Error creating plot: {str(e)}")
            # Create a simple fallback plot
            fig, ax = plt.subplots(figsize=(10, 8))
            if self.wn:
                try:
                    G = self.wn.get_graph()
                    pos = nx.spring_layout(G, seed=42)
                    nx.draw(G, pos, ax=ax, with_labels=False, node_size=50, font_size=6)
                    ax.set_title("Network Topology (Simplified)", fontweight='bold')
                    ax.axis('off')
                except:
                    ax.text(0.5, 0.5, "Unable to generate network plot", 
                           ha='center', va='center', fontsize=12)
            return fig
    
    def create_ieee_plot(self, data, title, xlabel, ylabel, filename):
        """Create IEEE style publication plot"""
        fig, ax = plt.subplots(figsize=(6, 4))
        
        if isinstance(data, pd.DataFrame):
            for column in data.columns[:5]:  # Limit to first 5 columns for clarity
                ax.plot(data.index / 3600, data[column], linewidth=1.5, alpha=0.8, label=str(column))
        elif isinstance(data, pd.Series):
            ax.plot(data.index / 3600, data.values, linewidth=1.5, color='#1E40AF')
        
        ax.set_xlabel(xlabel, fontweight='bold')
        ax.set_ylabel(ylabel, fontweight='bold')
        ax.set_title(title, fontsize=11, fontweight='bold')
        ax.grid(True, alpha=0.3, linestyle='--')
        if isinstance(data, pd.DataFrame) and len(data.columns) <= 5:
            ax.legend(loc='best', frameon=True, fancybox=True, shadow=True, fontsize=9)
        
        # IEEE style adjustments
        ax.spines['top'].set_visible(False)
        ax.spines['right'].set_visible(False)
        
        return fig

def main():
    """Main application function"""
    
    # Header
    st.markdown('<h1 class="main-header">💧 WDN Security Analysis Platform</h1>', unsafe_allow_html=True)
    st.markdown("""
    *PhD Research Application for EPANET Model Analysis with FDI/DOS Attack Simulation*
    """)
    
    if not WNTR_AVAILABLE:
        st.stop()
    
    # Initialize analyzer in session state
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
        st.markdown("### Status")
        
        if analyzer.wn:
            network_name = getattr(analyzer.wn, 'name', 'Unknown Network')
            st.success(f"✓ Network Loaded: {network_name}")
        
        if analyzer.results:
            st.success("✓ Baseline Simulation Complete")
        
        if hasattr(st.session_state, 'fdi_results'):
            st.info("✓ FDI Attack Simulated")
        
        if hasattr(st.session_state, 'dos_results'):
            st.info("✓ DoS Attack Simulated")
        
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
            # Display file info
            file_details = {"Filename": uploaded_file.name, "FileSize": f"{uploaded_file.size / 1024:.1f} KB"}
            st.write(file_details)
            
            # Preview first few lines
            if st.checkbox("Preview file content"):
                content = uploaded_file.getvalue().decode("utf-8")
                st.text_area("File Preview", content[:2000], height=200)
            
            # Load network
            if st.button("📥 Load Network", type="primary", use_container_width=True):
                with st.spinner("Loading network..."):
                    success, message = analyzer.load_inp_file(uploaded_file)
                    
                    if success:
                        st.success(message)
                        
                        # Display network properties
                        st.markdown('<h3 class="sub-header">Network Properties</h3>', unsafe_allow_html=True)
                        
                        properties = analyzer.get_network_properties()
                        
                        # Display metrics in a grid
                        cols = st.columns(3)
                        metrics = list(properties.items())
                        
                        for i in range(0, len(metrics), 3):
                            cols = st.columns(3)
                            for j in range(3):
                                if i + j < len(metrics):
                                    key, value = metrics[i + j]
                                    with cols[j]:
                                        st.markdown(f"""
                                        <div class="metric-card">
                                            <div style="font-size: 0.9rem; color: #6B7280;">{key}</div>
                                            <div style="font-size: 1.5rem; font-weight: 700; color: #1E40AF;">{value}</div>
                                        </div>
                                        """, unsafe_allow_html=True)
                        
                        # Add a separator
                        st.markdown("---")
                        
                        # Run baseline simulation section
                        st.markdown('<h3 class="sub-header">Baseline Simulation</h3>', unsafe_allow_html=True)
                        
                        if st.button("🚀 Run Baseline Simulation", type="primary", use_container_width=True):
                            with st.spinner("Running hydraulic simulation..."):
                                results = analyzer.simulate_hydraulics()
                                if results is not None:
                                    st.success("Baseline simulation completed successfully!")
                                    
                                    # Store baseline completion in session state
                                    st.session_state.baseline_completed = True
                                    st.session_state.baseline_results = True
                                    
                                    # Show quick results
                                    if hasattr(results.node, 'pressure'):
                                        avg_pressure = results.node['pressure'].mean().mean()
                                        st.metric("Average Network Pressure", f"{avg_pressure:.2f} m")
                                        
                                        # Also show min and max
                                        min_pressure = results.node['pressure'].min().min()
                                        max_pressure = results.node['pressure'].max().max()
                                        
                                        col1, col2, col3 = st.columns(3)
                                        with col1:
                                            st.metric("Min Pressure", f"{min_pressure:.2f} m")
                                        with col2:
                                            st.metric("Avg Pressure", f"{avg_pressure:.2f} m")
                                        with col3:
                                            st.metric("Max Pressure", f"{max_pressure:.2f} m")
                                    
                                    st.info("✅ Baseline simulation complete. You can now proceed to Attack Simulation.")
                    
                    else:
                        st.error(message)
    
    with col2:
        st.markdown("### Quick Start Guide")
        st.markdown("""
        **Step-by-Step:**
        
        1. **Upload** your .inp file
        2. **Load** the network
        3. **Run** baseline simulation
        4. **Visualize** the network
        5. **Simulate** attacks
        6. **Analyze** results
        7. **Export** for publication
        """)
        
        st.markdown("### Status Check")
        if analyzer.wn:
            st.success("✓ Network loaded")
        else:
            st.warning("✗ Network not loaded")
        
        if analyzer.results:
            st.success("✓ Baseline simulation complete")
        else:
            st.warning("✗ Baseline not run")

def render_visualization(analyzer):
    """Render network visualization section"""
    st.markdown('<h2 class="sub-header">📊 Network Visualization</h2>', unsafe_allow_html=True)
    
    if not analyzer.wn:
        st.warning("Please upload and load an EPANET .inp file first")
        st.info("Go to '📁 Upload & Overview' to load your network model")
        return
    
    col1, col2 = st.columns([3, 1])
    
    with col1:
        # Network plot
        st.markdown("### Network Topology")
        
        plot_type = st.selectbox(
            "Select visualization type:",
            ["Basic Network", "Pressure Distribution"]
        )
        
        # Create and display plot
        fig = analyzer.create_network_plot(plot_type)
        if fig:
            st.pyplot(fig)
            
            # Download button for the plot
            buf = BytesIO()
            fig.savefig(buf, format="png", dpi=300, bbox_inches='tight')
            buf.seek(0)
            
            st.download_button(
                label="📥 Download Plot",
                data=buf,
                file_name=f"network_visualization_{plot_type.replace(' ', '_')}.png",
                mime="image/png"
            )
    
    with col2:
        st.markdown("### Visualization Settings")
        
        # Network information
        if analyzer.wn:
            nodes = list(analyzer.wn.node_name_list)
            st.metric("Total Nodes", len(nodes))
            
            links = list(analyzer.wn.link_name_list)
            st.metric("Total Links", len(links))
            
            # Node type breakdown
            if analyzer.wn:
                junction_count = analyzer.wn.num_junctions
                reservoir_count = analyzer.wn.num_reservoirs
                tank_count = analyzer.wn.num_tanks
                
                col1, col2, col3 = st.columns(3)
                with col1:
                    st.metric("Junctions", junction_count)
                with col2:
                    st.metric("Reservoirs", reservoir_count)
                with col3:
                    st.metric("Tanks", tank_count)
        
        if st.button("🔄 Refresh View", use_container_width=True):
            st.rerun()

def render_attack_simulation(analyzer):
    """Render attack simulation section"""
    st.markdown('<h2 class="sub-header">⚡ Attack Simulation</h2>', unsafe_allow_html=True)
    
    if not analyzer.wn:
        st.warning("Please upload and load an EPANET .inp file first")
        st.info("Go to '📁 Upload & Overview' to load your network model")
        return
    
    # Check if baseline simulation has been run
    if not analyzer.results:
        st.markdown('<div class="warning-box">', unsafe_allow_html=True)
        st.warning("⚠️ **Baseline Simulation Required**")
        st.markdown("""
        Please run the baseline simulation first:
        
        1. Go to **'📁 Upload & Overview'**
        2. Upload your .inp file
        3. Click **'Load Network'**
        4. Click **'🚀 Run Baseline Simulation'**
        5. Return here after successful simulation
        """)
        st.markdown('</div>', unsafe_allow_html=True)
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
                ["Pressure Manipulation", "Flow Manipulation"],
                key="fdi_type"
            )
            
            attack_magnitude = st.slider(
                "Attack magnitude:",
                0.0, 1.0, 0.3, 0.05,
                help="Magnitude of false data injection (0-1 scale)",
                key="fdi_magnitude"
            )
            
            attack_duration = st.slider(
                "Attack duration (hours):",
                1, 24, 6,
                key="fdi_duration"
            )
        
        with col2:
            # Target selection
            st.markdown("#### Target Selection")
            
            if analyzer.wn:
                nodes = list(analyzer.wn.node_name_list)
                
                attack_strategy = st.radio(
                    "Attack strategy:",
                    ["Random nodes", "Specific nodes"],
                    key="fdi_strategy"
                )
                
                if attack_strategy == "Specific nodes":
                    target_nodes = st.multiselect(
                        "Select nodes to attack:",
                        nodes,
                        key="fdi_target_nodes"
                    )
                else:
                    n_attack = st.slider("Number of nodes to attack:", 
                                        1, min(10, len(nodes)), 3,
                                        key="fdi_n_nodes")
                    target_nodes = None
        
        # Run FDI attack
        if st.button("🚨 Simulate FDI Attack", type="primary", use_container_width=True, key="fdi_button"):
            with st.spinner("Simulating FDI attack..."):
                # Prepare target nodes if not specified
                if target_nodes is None and analyzer.wn:
                    nodes = list(analyzer.wn.node_name_list)
                    target_nodes = list(np.random.choice(nodes, n_attack, replace=False))
                
                # Run attack simulation
                attack_type_param = 'pressure' if 'Pressure' in attack_type else 'flow'
                attack_results = analyzer.simulate_fdi_attack(
                    target_nodes=target_nodes,
                    attack_magnitude=attack_magnitude,
                    attack_type=attack_type_param
                )
                
                if attack_results is not None:
                    st.session_state.fdi_results = attack_results
                    st.session_state.fdi_params = {
                        'type': attack_type,
                        'magnitude': attack_magnitude,
                        'duration': attack_duration,
                        'targets': target_nodes,
                        'strategy': attack_strategy
                    }
                    st.success("✅ FDI attack simulation completed!")
                    
                    # Show impact metrics
                    if analyzer.results and hasattr(st.session_state, 'fdi_results'):
                        if hasattr(analyzer.results.node, 'pressure') and hasattr(st.session_state.fdi_results.node, 'pressure'):
                            baseline_pressure = analyzer.results.node['pressure'].mean().mean()
                            attack_pressure = st.session_state.fdi_results.node['pressure'].mean().mean()
                            pressure_change = attack_pressure - baseline_pressure
                            impact_percent = abs((pressure_change) / baseline_pressure * 100) if baseline_pressure != 0 else 0
                            
                            col1, col2, col3 = st.columns(3)
                            with col1:
                                st.metric(
                                    label="Pressure Change",
                                    value=f"{pressure_change:.2f} m",
                                    delta=f"{impact_percent:.1f}%"
                                )
                            with col2:
                                st.metric(
                                    label="Nodes Attacked",
                                    value=len(target_nodes) if target_nodes else n_attack
                                )
                            with col3:
                                st.metric(
                                    label="Attack Magnitude",
                                    value=f"{attack_magnitude:.2f}"
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
                "Component to attack:",
                ["Pipes", "Pumps", "Valves"],
                key="dos_type"
            )
            
            attack_severity = st.slider(
                "Attack severity (% of components):",
                1, 50, 10,
                help="Percentage of components to disable",
                key="dos_severity"
            )
            
            recovery_time = st.slider(
                "Component disable time (hours):",
                1, 72, 24,
                key="dos_recovery"
            )
        
        with col2:
            st.markdown("#### Target Selection")
            
            if analyzer.wn:
                # Get components based on type
                if dos_type == "Pipes":
                    available_components = [link for link in analyzer.wn.link_name_list 
                                          if analyzer.wn.get_link(link).link_type == 'Pipe']
                elif dos_type == "Pumps":
                    available_components = [link for link in analyzer.wn.link_name_list 
                                          if analyzer.wn.get_link(link).link_type == 'Pump']
                elif dos_type == "Valves":
                    available_components = [link for link in analyzer.wn.link_name_list 
                                          if analyzer.wn.get_link(link).link_type == 'Valve']
                else:
                    available_components = []
                
                dos_strategy = st.radio(
                    "Attack strategy:",
                    ["Random components", "Specific components"],
                    key="dos_strategy"
                )
                
                if dos_strategy == "Specific components":
                    target_components = st.multiselect(
                        f"Select {dos_type.lower()} to disable:",
                        available_components,
                        key="dos_target_components"
                    )
                else:
                    n_attack = max(1, int(len(available_components) * attack_severity / 100))
                    st.info(f"Will randomly disable {n_attack} {dos_type.lower()}")
                    target_components = None
        
        # Run DoS attack
        if st.button("🚨 Simulate DoS Attack", type="primary", use_container_width=True, key="dos_button"):
            with st.spinner("Simulating DoS attack..."):
                # Prepare target components if not specified
                if target_components is None and analyzer.wn:
                    if len(available_components) > 0:
                        n_attack = max(1, int(len(available_components) * attack_severity / 100))
                        target_components = list(np.random.choice(available_components, 
                                                                min(n_attack, len(available_components)), 
                                                                replace=False))
                    else:
                        target_components = []
                
                dos_results, attacked_links = analyzer.simulate_dos_attack(
                    target_links=target_components,
                    attack_duration=recovery_time
                )
                
                if dos_results is not None:
                    st.session_state.dos_results = dos_results
                    st.session_state.dos_attacked_links = attacked_links
                    st.session_state.dos_params = {
                        'type': dos_type,
                        'severity': attack_severity,
                        'recovery': recovery_time,
                        'strategy': dos_strategy
                    }
                    st.success(f"✅ DoS attack simulation completed! {len(attacked_links)} components disabled.")
                    
                    # Show impact
                    if analyzer.results:
                        if hasattr(analyzer.results.link, 'flowrate') and hasattr(dos_results.link, 'flowrate'):
                            baseline_flow = analyzer.results.link['flowrate'].abs().mean().mean()
                            dos_flow = dos_results.link['flowrate'].abs().mean().mean()
                            if baseline_flow != 0:
                                flow_reduction = ((baseline_flow - dos_flow) / baseline_flow * 100)
                            else:
                                flow_reduction = 0
                            
                            col1, col2, col3 = st.columns(3)
                            with col1:
                                st.metric(
                                    label="Flow Reduction",
                                    value=f"{flow_reduction:.1f}%",
                                    delta="Negative impact" if flow_reduction > 0 else "No change"
                                )
                            with col2:
                                st.metric(
                                    label="Components Disabled",
                                    value=len(attacked_links)
                                )
                            with col3:
                                # Estimate affected nodes
                                affected_nodes = set()
                                for link in attacked_links:
                                    try:
                                        link_obj = analyzer.wn.get_link(link)
                                        affected_nodes.add(link_obj.start_node_name)
                                        affected_nodes.add(link_obj.end_node_name)
                                    except:
                                        pass
                                st.metric(
                                    label="Nodes Affected",
                                    value=len(affected_nodes)
                                )

def render_results_analysis(analyzer):
    """Render results analysis section"""
    st.markdown('<h2 class="sub-header">📈 Results Analysis</h2>', unsafe_allow_html=True)
    
    if not analyzer.results:
        st.markdown('<div class="warning-box">', unsafe_allow_html=True)
        st.warning("No simulation results available")
        st.markdown("Please run baseline simulation first in '📁 Upload & Overview'")
        st.markdown('</div>', unsafe_allow_html=True)
        return
    
    tab1, tab2, tab3 = st.tabs(["📊 Baseline Results", "⚡ Attack Comparison", "📉 Impact Metrics"])
    
    with tab1:
        st.markdown("### Baseline Simulation Results")
        
        # Select results to display
        result_type = st.selectbox(
            "Select result type:",
            ["Node Pressure", "Link Flow", "Node Demand"],
            key="baseline_result_type"
        )
        
        if result_type == "Node Pressure":
            if hasattr(analyzer.results.node, 'pressure'):
                data = analyzer.results.node['pressure']
                ylabel = "Pressure (m)"
            else:
                st.error("Pressure data not available")
                return
        elif result_type == "Link Flow":
            if hasattr(analyzer.results.link, 'flowrate'):
                data = analyzer.results.link['flowrate']
                ylabel = "Flow Rate (m³/s)"
            else:
                st.error("Flow data not available")
                return
        elif result_type == "Node Demand":
            if hasattr(analyzer.results.node, 'demand'):
                data = analyzer.results.node['demand']
                ylabel = "Demand (L/s)"
            else:
                st.error("Demand data not available")
                return
        
        # Select specific elements to plot
        if len(data.columns) > 0:
            elements = st.multiselect(
                "Select elements to display:",
                data.columns.tolist(),
                default=data.columns.tolist()[:min(3, len(data.columns))],
                key="baseline_elements"
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
            attack_options = []
            if hasattr(st.session_state, 'fdi_results'):
                attack_options.append("FDI Attack")
            if hasattr(st.session_state, 'dos_results'):
                attack_options.append("DoS Attack")
            
            if attack_options:
                attack_to_compare = st.selectbox(
                    "Select attack for comparison:",
                    attack_options,
                    key="attack_comparison"
                )
                
                # Select element for comparison
                if analyzer.wn and len(analyzer.wn.node_name_list) > 0:
                    compare_element = st.selectbox(
                        "Select node for comparison:",
                        analyzer.wn.node_name_list[:min(10, len(analyzer.wn.node_name_list))],
                        key="compare_element"
                    )
                    
                    if compare_element and hasattr(analyzer.results.node, 'pressure'):
                        fig, ax = plt.subplots(figsize=(8, 5))
                        
                        # Plot baseline
                        if compare_element in analyzer.results.node['pressure'].columns:
                            baseline = analyzer.results.node['pressure'][compare_element]
                            ax.plot(baseline.index / 3600, baseline.values, 
                                   label='Baseline', linewidth=2, color='#1E40AF')
                        
                        # Plot selected attack
                        if attack_to_compare == "FDI Attack" and hasattr(st.session_state, 'fdi_results'):
                            if compare_element in st.session_state.fdi_results.node['pressure'].columns:
                                fdi_data = st.session_state.fdi_results.node['pressure'][compare_element]
                                ax.plot(fdi_data.index / 3600, fdi_data.values, 
                                       label='FDI Attack', linewidth=2, color='#DC2626', linestyle='--')
                        
                        elif attack_to_compare == "DoS Attack" and hasattr(st.session_state, 'dos_results'):
                            if compare_element in st.session_state.dos_results.node['pressure'].columns:
                                dos_data = st.session_state.dos_results.node['pressure'][compare_element]
                                ax.plot(dos_data.index / 3600, dos_data.values, 
                                       label='DoS Attack', linewidth=2, color='#059669', linestyle='-.')
                        
                        ax.set_xlabel("Time (hours)", fontweight='bold')
                        ax.set_ylabel("Pressure (m)", fontweight='bold')
                        ax.set_title(f"Pressure at Node {compare_element}", fontweight='bold')
                        ax.legend()
                        ax.grid(True, alpha=0.3, linestyle='--')
                        
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
                if hasattr(analyzer.results.node, 'pressure') and hasattr(st.session_state.fdi_results.node, 'pressure'):
                    baseline_pressure = analyzer.results.node['pressure']
                    fdi_pressure = st.session_state.fdi_results.node['pressure']
                    
                    pressure_diff = (fdi_pressure - baseline_pressure).abs()
                    max_deviation = pressure_diff.max().max()
                    mean_deviation = pressure_diff.mean().mean()
                    
                    impact_metrics['FDI'] = {
                        'Max Pressure Deviation (m)': max_deviation,
                        'Mean Pressure Deviation (m)': mean_deviation,
                        'Nodes with >1m deviation': (pressure_diff.max() > 1).sum(),
                        'Impact Index': mean_deviation * 100
                    }
            
            if hasattr(st.session_state, 'dos_results'):
                # DoS impact metrics
                if hasattr(analyzer.results.link, 'flowrate') and hasattr(st.session_state.dos_results.link, 'flowrate'):
                    baseline_flow = analyzer.results.link['flowrate'].abs()
                    dos_flow = st.session_state.dos_results.link['flowrate'].abs()
                    
                    # Avoid division by zero
                    baseline_flow_nonzero = baseline_flow.replace(0, np.nan)
                    dos_flow_nonzero = dos_flow.replace(0, np.nan)
                    
                    if not baseline_flow_nonzero.empty:
                        flow_reduction = ((baseline_flow_nonzero - dos_flow_nonzero) / baseline_flow_nonzero * 100)
                        max_reduction = flow_reduction.max().max()
                        mean_reduction = flow_reduction.mean().mean()
                        
                        impact_metrics['DoS'] = {
                            'Max Flow Reduction (%)': max_reduction if not np.isnan(max_reduction) else 0,
                            'Mean Flow Reduction (%)': mean_reduction if not np.isnan(mean_reduction) else 0,
                            'Links with >20% Reduction': (flow_reduction.max() > 20).sum() if not flow_reduction.empty else 0,
                            'Network Resilience Index': max(0, 100 - (mean_reduction if not np.isnan(mean_reduction) else 0))
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
        st.warning("No simulation results to export. Please run baseline simulation first.")
        return
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.markdown("### Export Data")
        
        # Export options
        export_format = st.selectbox(
            "Select export format:",
            ["CSV", "Excel"],
            key="export_format"
        )
        
        data_to_export = st.multiselect(
            "Select data to export:",
            ["Baseline Results", "FDI Attack Results", "DoS Attack Results", 
             "Network Properties", "Attack Parameters"],
            default=["Baseline Results"],
            key="data_to_export"
        )
        
        filename = st.text_input(
            "Filename prefix:",
            value=f"wdn_analysis_{datetime.now().strftime('%Y%m%d_%H%M%S')}",
            key="export_filename"
        )
    
    with col2:
        st.markdown("### Export Settings")
        
        include_summary = st.checkbox("Include summary statistics", value=True, key="include_summary")
        timestamp_in_filename = st.checkbox("Add timestamp to filename", value=True, key="timestamp_in_filename")
        
        if timestamp_in_filename:
            export_filename = f"{filename}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        else:
            export_filename = filename
    
    # Export button
    if st.button("📥 Export Data", type="primary", use_container_width=True, key="export_button"):
        with st.spinner("Preparing export..."):
            export_items = []
            
            if "Baseline Results" in data_to_export and analyzer.results:
                # Export pressure data
                if hasattr(analyzer.results.node, 'pressure'):
                    pressure_df = analyzer.results.node['pressure']
                    if include_summary:
                        summary_df = pressure_df.describe()
                        export_items.append(("baseline_pressure_summary", summary_df))
                    export_items.append(("baseline_pressure", pressure_df))
                
                # Export flow data
                if hasattr(analyzer.results.link, 'flowrate'):
                    flow_df = analyzer.results.link['flowrate']
                    if include_summary:
                        summary_df = flow_df.describe()
                        export_items.append(("baseline_flow_summary", summary_df))
                    export_items.append(("baseline_flow", flow_df))
            
            if "FDI Attack Results" in data_to_export and hasattr(st.session_state, 'fdi_results'):
                if hasattr(st.session_state.fdi_results.node, 'pressure'):
                    fdi_pressure = st.session_state.fdi_results.node['pressure']
                    export_items.append(("fdi_pressure", fdi_pressure))
            
            if "DoS Attack Results" in data_to_export and hasattr(st.session_state, 'dos_results'):
                if hasattr(st.session_state.dos_results.node, 'pressure'):
                    dos_pressure = st.session_state.dos_results.node['pressure']
                    export_items.append(("dos_pressure", dos_pressure))
            
            if "Network Properties" in data_to_export and analyzer.wn:
                props = analyzer.get_network_properties()
                props_df = pd.DataFrame([props])
                export_items.append(("network_properties", props_df))
            
            if "Attack Parameters" in data_to_export:
                attack_params = {}
                if hasattr(st.session_state, 'fdi_params'):
                    attack_params['fdi'] = st.session_state.fdi_params
                if hasattr(st.session_state, 'dos_params'):
                    attack_params['dos'] = st.session_state.dos_params
                if attack_params:
                    # Convert to DataFrame-friendly format
                    flat_params = {}
                    for attack_type, params in attack_params.items():
                        for key, value in params.items():
                            if isinstance(value, list):
                                flat_params[f"{attack_type}_{key}"] = ", ".join(map(str, value))
                            else:
                                flat_params[f"{attack_type}_{key}"] = value
                    params_df = pd.DataFrame([flat_params])
                    export_items.append(("attack_parameters", params_df))
            
            # Create download links
            st.markdown("### Download Files")
            
            for data_name, data_df in export_items:
                if isinstance(data_df, pd.DataFrame) and not data_df.empty:
                    if export_format == "CSV":
                        csv = data_df.to_csv()
                        b64 = base64.b64encode(csv.encode()).decode()
                        download_link = f'<a href="data:file/csv;base64,{b64}" download="{export_filename}_{data_name}.csv">📥 Download {data_name}.csv</a>'
                    else:  # Excel
                        excel_buffer = BytesIO()
                        with pd.ExcelWriter(excel_buffer, engine='openpyxl') as writer:
                            data_df.to_excel(writer, sheet_name=data_name[:31])
                        excel_buffer.seek(0)
                        b64 = base64.b64encode(excel_buffer.read()).decode()
                        download_link = f'<a href="data:application/vnd.openxmlformats-officedocument.spreadsheetml.sheet;base64,{b64}" download="{export_filename}_{data_name}.xlsx">📥 Download {data_name}.xlsx</a>'
                    
                    st.markdown(download_link, unsafe_allow_html=True)
            
            if export_items:
                st.success("✅ Export files ready for download!")
            else:
                st.warning("No data selected for export")

if __name__ == "__main__":
    main()







