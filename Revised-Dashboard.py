import dash
from dash import dcc, html, Input, Output
import plotly.graph_objects as go
import pandas as pd
import re
import networkx as nx
import os

#############################
# DATA HANDLING FUNCTIONS
#############################

def load_and_clean_data(file_path):
    """Load Excel file and clean technique names by removing bracketed examples"""
    sheets = [
        'Threat Actors', 'Threat Surface', 'Reconnaissance', 'Initial Access',
        'Credential Access', 'Discovery', 'Defense Evasion', 'Collection', 'Impact'
    ]
    data = {}
    for sheet in sheets:
        try:
            df = pd.read_excel(file_path, sheet_name=sheet)
            if sheet == 'Threat Actors':
                if 'Technique' in df.columns:
                    pass
                elif ' Threat Actor' in df.columns:
                    df = df.rename(columns={' Threat Actor': 'Technique'})
                elif 'Unnamed: 0' in df.columns and df.columns[1] == 'Technique':
                    df = df.drop('Unnamed: 0', axis=1)
            data[sheet] = df
        except Exception as e:
            print(f"❌ Error loading sheet {sheet}: {e}")
            data[sheet] = pd.DataFrame()

    def clean_technique_name(name):
        if pd.isna(name):
            return ""
        return re.sub(r'\s*\([^\)]*\)', '', str(name)).strip()

    for sheet in sheets[1:]:
        if not data[sheet].empty and 'Technique' in data[sheet].columns:
            data[sheet]['Technique'] = data[sheet]['Technique'].apply(clean_technique_name)

    return data

def extract_threat_actor_from_column(column_name, threat_actors):
    """Extract threat actor name from column description"""
    if pd.isna(column_name): return None
    column_str = str(column_name)
    for actor in threat_actors:
        if actor in column_str: return actor
    return None

def build_combined_df(data):
    """Build combined dataframe from all tactics"""
    if 'Threat Actors' not in data or data['Threat Actors'].empty:
        print("❌ No threat actors data found")
        return pd.DataFrame()
    threat_actors_df = data['Threat Actors']
    if 'Technique' not in threat_actors_df.columns:
        print("❌ No 'Technique' column in Threat Actors sheet")
        return pd.DataFrame()
    threat_actors = threat_actors_df['Technique'].dropna().unique().tolist()
    tactics = [
        'Threat Surface', 'Reconnaissance', 'Initial Access', 'Credential Access',
        'Discovery', 'Defense Evasion', 'Collection', 'Impact'
    ]
    combined_rows = []
    for tactic in tactics:
        df = data.get(tactic, pd.DataFrame())
        if df.empty: continue
        df_copy = df.copy()
        column_col = technique_col = frequency_col = None
        for col in df_copy.columns:
            if 'column' in str(col).lower() or col == 'Column':
                column_col = col
            elif 'technique' in str(col).lower() or col == 'Technique':
                technique_col = col
            elif 'frequency' in str(col).lower() or col == 'Frequency':
                frequency_col = col
        if not all([technique_col, frequency_col]): continue
        if column_col:
            df_copy['Threat_Actor'] = df_copy[column_col].apply(lambda x: extract_threat_actor_from_column(x, threat_actors))
        else:
            df_copy['Threat_Actor'] = None
        df_copy['Tactic'] = tactic
        df_filtered = df_copy[df_copy['Threat_Actor'].notnull()].copy()
        if not df_filtered.empty:
            required_cols = ['Threat_Actor', technique_col, frequency_col, 'Tactic']
            df_filtered = df_filtered[required_cols].copy()
            df_filtered.columns = ['Threat_Actor', 'Technique', 'Frequency', 'Tactic']
            combined_rows.append(df_filtered)
    if combined_rows:
        combined_df = pd.concat(combined_rows, ignore_index=True)
        return combined_df
    return pd.DataFrame()

def compute_actor_scores(heatmap_matrix):
    """Compute composite scores for threat actors"""
    actor_scores = {}
    for actor in heatmap_matrix.index:
        actor_data = heatmap_matrix.loc[actor]
        total_activity = actor_data.sum()
        breadth = len(actor_data[actor_data >= 3])
        active_techniques = actor_data[actor_data > 0]
        intensity = active_techniques.mean() if len(active_techniques) > 0 else 0
        composite_score = (total_activity * 0.5) + (breadth * 0.3) + (intensity * 0.2)
        actor_scores[actor] = composite_score
    return actor_scores

def get_all_actors_ranked(actor_scores):
    return [actor for actor, _ in sorted(actor_scores.items(), key=lambda x: x[1], reverse=True)]

def get_top_3_actors(all_actors):
    return all_actors[:3]

def extract_critical_paths_by_layer(combined_df, actors):
    """Extract critical path techniques for all actors by tactic layer"""
    tactics = [
        'Threat Surface', 'Reconnaissance', 'Initial Access', 'Credential Access',
        'Discovery', 'Defense Evasion', 'Collection', 'Impact'
    ]
    critical_paths = {}
    for actor in actors:
        actor_df = combined_df[combined_df['Threat_Actor'] == actor]
        critical_paths[actor] = []
        for tactic in tactics:
            tactic_df = actor_df[actor_df['Tactic'] == tactic]
            if not tactic_df.empty:
                max_freq = tactic_df['Frequency'].max()
                critical_techs = tactic_df[tactic_df['Frequency'] >= max_freq * 0.8].head(2)
                for _, row in critical_techs.iterrows():
                    critical_paths[actor].append({
                        'tactic': tactic,
                        'technique': row['Technique'],
                        'frequency': row['Frequency']
                    })
    return critical_paths, tactics

def process_file(file_path):
    """Process a single threat file and return analysis results"""
    data = load_and_clean_data(file_path)
    combined_df = build_combined_df(data)
    if combined_df.empty: return None
    pivot = combined_df.pivot_table(
        index='Threat_Actor',
        columns=['Tactic', 'Technique'],
        values='Frequency',
        aggfunc='sum',
        fill_value=0
    )
    actor_scores = compute_actor_scores(pivot)
    all_actors = get_all_actors_ranked(actor_scores)
    top_3_actors = get_top_3_actors(all_actors)
    critical_paths, tactics = extract_critical_paths_by_layer(combined_df, all_actors)
    filename = os.path.basename(file_path).replace('.xlsx', '')
    return {
        'combined_df': combined_df,
        'all_actors': all_actors,
        'top_3_actors': top_3_actors,
        'critical_paths': critical_paths,
        'tactics': tactics,
        'filename': filename
    }

def prepare_all_datasets():
    file_patterns = [
        'T1-Identification-of-IoT-User.xlsx',
        'T2-Identification-of-IoT-device.xlsx',
        'T3-Localization-and-Tracking-of-Smart-IoT-Device-and-User.xlsx',
        'T4-Profiling.xlsx',
        'T5-Impersonation-of-IoT-user.xlsx',
        'T6-Linkage-of-IoT-User-and-Device.xlsx',
        'T7-Data-Leakage.xlsx',
        'T8-Jurisdiction-Risk.xlsx',
        'T9-Lifecycle-Transition.xlsx',
        'T10-Inventory-Attack.xlsx',
        'T11-Data-Tampering.xlsx',
        'T12-Utility-Monitoring-and-Controlling.xlsx'
    ]
    datasets = {}
    for file_path in file_patterns:
        if os.path.exists(file_path):
            result = process_file(file_path)
            if result:
                datasets[result['filename']] = result
    return datasets

#########################################
# NETWORK LAYOUT & DYNAMIC TACTIC PLACEMENT
#########################################

def create_network_layout(critical_paths, tactics, actors, top_3_actors, vertical_spacing):
    """Builds network Graph and returns node positions dynamically stacked based on number of actors"""
    G = nx.DiGraph()
    color_map = {
        'Cloud Provider': '#808080',
        'Skilled Outsider': '#006400',
        'Service Provider': '#007bff',
        'Third Party Provider': '#f08080',
        'Security Agent': '#b19cd9',
        'Government Authority': '#ffcc99',
        'Skilled Insider': '#ffb6c1',
        'Unskilled Insider': '#fffacd'
    }
    pos = {}
    layer_width = 30
    # Actor nodes
    for i, actor in enumerate(actors):
        is_top3 = actor in top_3_actors
        G.add_node(f"Actor_{actor}",
                   label=actor,
                   node_type='actor',
                   layer=0,
                   frequency=0,
                   actor=actor,
                   is_top_3=is_top3)
        pos[f"Actor_{actor}"] = (-8, i * vertical_spacing)
    # Technique nodes
    for tactic_idx, tactic in enumerate(tactics):
        layer_x = (tactic_idx + 1) * layer_width
        tactic_techniques_all = []
        for actor in actors:
            tactic_techniques = [entry for entry in critical_paths[actor] if entry['tactic'] == tactic]
            for entry in tactic_techniques:
                tactic_techniques_all.append((actor, entry))
        total_nodes = len(tactic_techniques_all)
        if total_nodes > 0:
            start_y = -(total_nodes - 1) * vertical_spacing / 2
            for node_idx, (actor, entry) in enumerate(tactic_techniques_all):
                node_id = f"{actor}_{tactic}_{entry['technique']}"
                label_text = entry['technique'][:30] + "..." if len(entry['technique']) > 30 else entry['technique']
                is_top3 = actor in top_3_actors
                G.add_node(node_id,
                           label=label_text,
                           full_label=entry['technique'],
                           node_type='technique',
                           layer=tactic_idx + 1,
                           frequency=entry['frequency'],
                           tactic=tactic,
                           actor=actor,
                           is_top_3=is_top3)
                node_y = start_y + node_idx * vertical_spacing
                pos[node_id] = (layer_x, node_y)
    # Edges (actor -> threat surface) - NEW ADDITION
    for actor in actors:
        is_top_3 = actor in top_3_actors
        threat_surface_techniques = [entry for entry in critical_paths[actor] if entry['tactic'] == 'Threat Surface']
        for entry in threat_surface_techniques:
            source = f"Actor_{actor}"
            target = f"{actor}_Threat Surface_{entry['technique']}"
            if source in G.nodes and target in G.nodes:
                G.add_edge(source, target, weight=entry['frequency'], actor=actor, is_top_3=is_top_3)
    # Edges (between consecutive tactics)
    for actor in actors:
        is_top_3 = actor in top_3_actors
        for i in range(len(tactics) - 1):
            current_tactic = tactics[i]
            next_tactic = tactics[i + 1]
            current_techniques = [entry for entry in critical_paths[actor] if entry['tactic'] == current_tactic]
            next_techniques = [entry for entry in critical_paths[actor] if entry['tactic'] == next_tactic]
            for curr_entry in current_techniques:
                for next_entry in next_techniques:
                    source = f"{actor}_{current_tactic}_{curr_entry['technique']}"
                    target = f"{actor}_{next_tactic}_{next_entry['technique']}"
                    if source in G.nodes and target in G.nodes:
                        weight = (curr_entry['frequency'] + next_entry['frequency']) / 2
                        G.add_edge(source, target, weight=weight, actor=actor, is_top_3=is_top_3)
    return G, pos, color_map

def get_dynamic_spacing(num_visible_actors):
    """Adjust spacing depending on how many actors are shown"""
    if num_visible_actors <= 3:
        return 4.0
    elif num_visible_actors <= 6:
        return 6.0
    else:
        return 8.0

def get_annotation_y_offset(pos, actors, tactics):
    """Places tactic labels just above the topmost node currently visible"""
    all_y = []
    for node, (x, y) in pos.items():
        for actor in actors:
            if f"{actor}_" in node or f"Actor_{actor}" == node:
                all_y.append(y)
    return (max(all_y)+4) if all_y else 2

def create_network_figure(G, pos, color_map, all_actors, top_3_actors, visible_actors, filename, tactics):
    # Prepare traces
    edge_traces, node_traces, label_traces = [], [], []
    # Edges
    for actor in all_actors:
        # Only plot if actor is visible
        if actor not in visible_actors: continue
        edge_x, edge_y = [], []
        is_top_3 = actor in top_3_actors
        for edge in G.edges():
            if G.edges[edge].get('actor') == actor:
                x0, y0 = pos[edge[0]]
                x1, y1 = pos[edge[1]]
                edge_x.extend([x0, x1, None])
                edge_y.extend([y0, y1, None])
        line_width = 4 if is_top_3 else 2
        opacity = 0.92 if is_top_3 else 0.3
        line_color = color_map.get(actor, '#2c3e50')
        edge_trace = go.Scatter(
            x=edge_x, y=edge_y,
            line=dict(width=line_width, color=line_color),
            opacity=opacity,
            hoverinfo='none', mode='lines',
            showlegend=False, visible=True
        )
        edge_traces.append(edge_trace)
    # Nodes
    fixed_node_size = 40
    for actor in all_actors:
        if actor not in visible_actors: continue
        actor_nodes = [node for node in G.nodes if G.nodes[node].get('actor') == actor]
        is_top_3 = actor in top_3_actors
        node_x, node_y, node_info, node_sizes, node_colors = [], [], [], [], []
        for node in actor_nodes:
            x, y = pos[node]
            node_data = G.nodes[node]
            label = node_data['label']
            frequency = node_data['frequency']
            node_type = node_data['node_type']
            if node_type == 'actor':
                node_info.append(f"{'TOP 3 ' if is_top_3 else ''}Threat Actor: {label}")
                node_colors.append(color_map.get(actor, '#34495e'))
            else:
                tactic = node_data['tactic']
                full_label = node_data.get('full_label', label)
                node_info.append(f"Tactic: {tactic}\nTechnique: {full_label}\nFrequency: {frequency}\nActor: {actor}{' (TOP 3)' if is_top_3 else ''}")
                node_colors.append(color_map.get(actor, '#7f8c8d'))
            node_x.append(x)
            node_y.append(y)
            node_sizes.append(fixed_node_size)
        line_width = 3 if is_top_3 else 1
        opacity = 1.0 if is_top_3 else 0.55
        node_trace = go.Scatter(
            x=node_x, y=node_y, mode='markers',
            hoverinfo='text', hovertext=node_info,
            marker=dict(size=node_sizes, color=node_colors, line=dict(width=line_width, color='white'), opacity=opacity),
            name=f"{'⭐ ' if is_top_3 else '• '}{actor}",
            visible=True
        )
        node_traces.append(node_trace)
        # Labels
        label_x = [x + 4.5 for x in node_x]
        label_y = [y + 0.3 for y in node_y]
        label_text = [f"{'⭐' if is_top_3 else ''} {G.nodes[node]['label']}" if G.nodes[node]['node_type'] == 'actor' else G.nodes[node]['label'] for node in actor_nodes]
        if label_x:
            label_trace = go.Scatter(
                x=label_x, y=label_y, mode='text',
                text=label_text,
                textfont=dict(family='Arial', size=11, color='#2c3e50'),
                showlegend=False, visible=True, hoverinfo='none'
            )
            label_traces.append(label_trace)
    # Tactic Annotations
    annotation_y = get_annotation_y_offset(pos, visible_actors, tactics)
    tactic_annotations = []
    for i, tactic in enumerate(tactics):
        tactic_annotations.append(dict(
            x=(i + 1) * 30,
            y=annotation_y,
            text=f"{tactic}",
            showarrow=False,
            font=dict(size=14, color="#2c3e50", family="Arial Black"),
            bgcolor="rgba(255,255,255,0.96)", bordercolor="#bdc3c7", borderwidth=2
        ))
    all_traces = edge_traces + node_traces + label_traces
    fig = go.Figure(data=all_traces)
    # Layout
    fig.update_layout(
        title=dict(
            text=f"IoT Privacy Threat Analysis: {filename} | ⭐ = Top 3 Threat Actors | • = Other Actors",
            x=0.5, font=dict(size=19, family="Arial", color="#2c3e50")
        ),
        showlegend=True,
        hovermode='closest',
        margin=dict(b=80, l=120, r=50, t=180),
        xaxis=dict(showgrid=False, zeroline=False, showticklabels=False, range=[-12, 270]),
        yaxis=dict(showgrid=False, zeroline=False, showticklabels=False),
        plot_bgcolor='#f8f9fa',
        paper_bgcolor='white',
        font=dict(family="Arial", size=12, color="#2c3e50"),
        annotations=tactic_annotations,
    )
    return fig

#############################
# DASHBOARD LAYOUT & CALLBACKS
#############################

app = dash.Dash(__name__, external_stylesheets=[
    'https://fonts.googleapis.com/css2?family=Inter:wght@300;400;600;700&display=swap'
])

app.title = "IoT Privacy Threat Analysis Dashboard"

custom_styles = {
    'container': {'maxWidth': '2000px', 'margin': '0 auto', 'padding': '20px', 'backgroundColor': '#f8f9fa'},
    'header': {'textAlign': 'center', 'marginBottom': '20px', 'padding': '30px',
               'backgroundColor': 'white', 'borderRadius': '15px',
               'boxShadow': '0 4px 6px rgba(0,0,0,0.1)'},
    'title': {'fontSize': '2.5rem', 'fontWeight': '700', 'color': '#2c3e50', 'marginBottom': '10px'},
    'subtitle': {'fontSize': '1.2rem', 'color': '#7f8c8d', 'fontStyle': 'italic', 'fontWeight': '300'},
    'controls': {'backgroundColor': 'white', 'padding': '20px', 'borderRadius': '15px', 'marginBottom': '10px',
                 'boxShadow': '0 4px 6px rgba(0,0,0,0.1)', 'position': 'relative', 'zIndex': '1000'},
    'dropdown_label': {'fontSize': '1.1rem', 'fontWeight': '600', 'color': '#2c3e50',
                       'marginBottom': '10px', 'display': 'block'},
    'info_panel': {'backgroundColor': 'white', 'padding': '25px',
                   'borderRadius': '15px', 'marginTop': '20px',
                   'boxShadow': '0 4px 6px rgba(0,0,0,0.1)', 'border': '2px solid #e3f2fd'}
}

all_datasets = prepare_all_datasets()

if not all_datasets:
    app.layout = html.Div([
        html.Div([
            html.H1("⚠️ No Datasets Found", style={**custom_styles['title'], 'color': '#e74c3c'}),
            html.P("Please ensure the required Excel files are in the same directory as this script.",
                   style={'fontSize': '1.1rem', 'color': '#7f8c8d'}),
            html.Div([
                html.H3("Required Files:", style={'color': '#2c3e50', 'marginBottom': '15px'}),
                html.Ul([html.Li(f"T{i}-*.xlsx") for i in range(1, 13)],
                        style={'textAlign': 'left', 'display': 'inline-block'})
            ])
        ], style=custom_styles['header'])
    ], style=custom_styles['container'])
else:
    app.layout = html.Div([
        html.Div([
            html.H1("🛡️ IoT Privacy Threat Actor Analysis Dashboard", style=custom_styles['title']),
            html.P("Interactive network analysis of IoT privacy threats across different attack scenarios",
                   style=custom_styles['subtitle'])
        ], style=custom_styles['header']),
        # Controls
        html.Div([
            dcc.Store(id='top3-only-store', data=False),
            html.Label("🎯 Select Threat Scenario:", style=custom_styles['dropdown_label']),
            dcc.Dropdown(
                id='dataset-dropdown',
                options=[
                    {'label': f"{filename.replace('-', ' ').replace('T', 'T')} - Top 3: {', '.join(data['top_3_actors'])}",
                     'value': filename} for filename, data in all_datasets.items()
                ],
                value=list(all_datasets.keys())[0] if all_datasets else None,
                clearable=False,
                style={'fontSize': '1rem', 'zIndex': '999'}
            ),
            html.Button("⭐ Top 3 Only", id="top3-only-toggle", n_clicks=0,
                        style={'marginTop': '10px', 'backgroundColor': '#3498db', 'color': 'white',
                               'border': 'none', 'padding': '8px 16px', 'borderRadius': '5px',
                               'cursor': 'pointer'}),
        ], style=custom_styles['controls']),
        dcc.Loading(
            id="loading-graph", type="circle", color="#667eea",
            children=[
                dcc.Graph(id='network-graph', style={'height': '1000px', 'backgroundColor': 'white', 'borderRadius': '15px'}),
                html.Div(id='dataset-info', style=custom_styles['info_panel'])
            ], style=custom_styles['container']
        ),
    ], style=custom_styles['container'])

@app.callback(
    Output('top3-only-store', 'data'),
    Input('top3-only-toggle', 'n_clicks'),
    prevent_initial_call=True
)
def toggle_top3_only(n_clicks):
    return n_clicks % 2 == 1  # Odd clicks = True (Top 3 Only active)

@app.callback(
    [Output('network-graph', 'figure'), Output('dataset-info', 'children')],
    [Input('dataset-dropdown', 'value'), Input('top3-only-store', 'data')]
)
def update_dashboard(selected_dataset, top3_only):
    if not selected_dataset or selected_dataset not in all_datasets:
        return go.Figure(), html.Div("No dataset selected")
    dataset = all_datasets[selected_dataset]
    if top3_only:
        visible_actors = dataset['top_3_actors']
    else:
        visible_actors = dataset['all_actors']
    spacing = get_dynamic_spacing(len(visible_actors))
    G, pos, color_map = create_network_layout(
        critical_paths=dataset['critical_paths'],
        tactics=dataset['tactics'],
        actors=visible_actors,
        top_3_actors=dataset['top_3_actors'],
        vertical_spacing=spacing
    )
    fig = create_network_figure(
        G=G,
        pos=pos,
        color_map=color_map,
        all_actors=dataset['all_actors'],
        top_3_actors=dataset['top_3_actors'],
        visible_actors=visible_actors,
        filename=dataset['filename'],
        tactics=dataset['tactics']
    )
    info_content = html.Div([
        html.H3(f"📊 Analysis: {dataset['filename'].replace('-', ' ')}",
                style={'color': '#2c3e50', 'marginBottom': '20px', 'fontSize': '1.5rem'}),
        html.Div([
            html.Div([
                html.H4("🏆", style={'fontSize': '2rem', 'margin': '0', 'color': '#f39c12'}),
                html.P("Top 3 Actors", style={'margin': '5px 0', 'fontWeight': '600'}),
                html.P(", ".join(dataset['top_3_actors']),
                       style={'margin': '0', 'color': '#e74c3c', 'fontSize': '0.9rem'})
            ], style={'textAlign': 'center', 'padding': '15px', 'backgroundColor': '#fff3cd',
                      'borderRadius': '10px', 'border': '2px solid #f39c12'}),
            html.Div([
                html.H4("👥", style={'fontSize': '2rem', 'margin': '0', 'color': '#3498db'}),
                html.P("Total Actors", style={'margin': '5px 0', 'fontWeight': '600'}),
                html.P(str(len(dataset['all_actors'])),
                       style={'margin': '0', 'color': '#3498db', 'fontSize': '1.2rem', 'fontWeight': 'bold'})
            ], style={'textAlign': 'center', 'padding': '15px', 'backgroundColor': '#d1ecf1',
                      'borderRadius': '10px', 'border': '2px solid #3498db'}),
            html.Div([
                html.H4("📈", style={'fontSize': '2rem', 'margin': '0', 'color': '#27ae60'}),
                html.P("Analysis Tactics", style={'margin': '5px 0', 'fontWeight': '600'}),
                html.P(str(len(dataset['tactics'])),
                       style={'margin': '0', 'color': '#27ae60', 'fontSize': '1.2rem', 'fontWeight': 'bold'})
            ], style={'textAlign': 'center', 'padding': '15px', 'backgroundColor': '#d4edda',
                      'borderRadius': '10px', 'border': '2px solid #27ae60'})
        ], style={'display': 'grid', 'gridTemplateColumns': '1fr 1fr 1fr', 'gap': '20px', 'marginBottom': '20px'}),
        html.Div([
            html.H4("💡 How to Use:", style={'color': '#2c3e50', 'marginBottom': '10px'}),
            html.Ul([
                html.Li("✨ Dropdown is positioned above tactics for best UX"),
                html.Li("✨ Click 'Top 3 Only' button to focus on critical actors with tight tactic spacing"),
                html.Li("✨ Tactics labels auto-align based on visible network structure"),
                html.Li("Use dropdown in the network graph to filter by actor group"),
                html.Li("Click 'Toggle Labels' button in bottom-right corner to show/hide node labels"),
                html.Li("Hover over nodes to see detailed information"),
                html.Li("⭐ indicates Top 3 most critical threat actors"),
                html.Li("🎨 Color coding for different threat actor categories is preserved")
            ], style={'textAlign': 'left', 'color': '#7f8c8d'})
        ], style={'backgroundColor': '#f8f9fa', 'padding': '15px', 'borderRadius': '10px',
                  'border': '1px solid #dee2e6'})
    ])
    return fig, info_content

if __name__ == '__main__':
    print(f"\n🎉 Enhanced Dashboard ready with {len(all_datasets)} datasets!")
    print("🚀 Starting optimized dashboard server...")
    app.run(debug=True)
