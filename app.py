import streamlit as st
import wntr
from pyvis.network import Network
import tempfile
import streamlit.components.v1 as components

st.set_page_config(layout="wide")
st.title("WDN CPS Security Testbed")

uploaded_file = st.file_uploader("Upload EPANET .inp file", type=["inp"])

if uploaded_file:
    with open("network.inp", "wb") as f:
        f.write(uploaded_file.getbuffer())

    wn = wntr.network.WaterNetworkModel("network.inp")

    col1, col2 = st.columns([3, 1])

    with col1:
        st.subheader("Water Distribution Network")
        net = Network(height="600px", width="100%", directed=False)
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
        components.html(open(tmp.name).read(), height=600)

    with col2:
        st.subheader("Component Inspector")
        comp_type = st.selectbox("Component Type", ["Node", "Link"])

        if comp_type == "Node":
            node_id = st.selectbox("Node ID", wn.node_name_list)
            node = wn.get_node(node_id)
            st.json(node.__dict__)

        else:
            link_id = st.selectbox("Link ID", wn.link_name_list)
            link = wn.get_link(link_id)
            st.json(link.__dict__)
