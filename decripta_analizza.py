import streamlit as st
import pandas as pd
import base64
import numpy as np
import matplotlib.pyplot as plt
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import io
from datetime import datetime, timedelta
import altair as alt

def password_to_key(password):
    """
    Converts a password into a valid Fernet key using a predefined salt.
    """
    # Using a fixed salt (not ideal for security, but practical)
    salt = b'ExcelCryptoFixedSalt'  # Fixed salt
    
    # Derive a key from password using PBKDF2
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    
    # Key derivation from password
    key_bytes = kdf.derive(password.encode('utf-8'))
    
    # Convert to Fernet format (URL-safe base64)
    key = base64.urlsafe_b64encode(key_bytes)
    
    return key

def decrypt_cell_value(value, cipher):
    """Decrypts a single cell value"""
    if value is None or pd.isna(value):
        return value
    
    try:
        # Convert from base64
        encrypted_bytes = base64.b64decode(value.encode('utf-8'))
        # Decrypt the value
        decrypted_bytes = cipher.decrypt(encrypted_bytes)
        # Convert to string
        decrypted_str = decrypted_bytes.decode('utf-8')
        
        # Attempt to convert numbers to float or int
        try:
            if '.' in decrypted_str:
                return float(decrypted_str)
            else:
                try:
                    return int(decrypted_str)
                except ValueError:
                    return decrypted_str
        except ValueError:
            return decrypted_str
    except Exception as e:
        return f"ERROR: {str(e)}"

@st.cache_data
def decrypt_dataframe_cached(encrypted_df_json, password):
    """
    Cached version of decrypt_dataframe function.
    Accepts DataFrame as JSON for compatibility with st.cache_data.
    """
    encrypted_df = pd.read_json(encrypted_df_json)
    
    try:
        # Convert password to Fernet key
        key = password_to_key(password)
        
        # Create encryption object
        cipher = Fernet(key)
        
        # Create a copy of the DataFrame
        decrypted_df = encrypted_df.copy()
        
        # Decrypt each value in each column
        for col in decrypted_df.columns:
            decrypted_df[col] = decrypted_df[col].apply(lambda x: decrypt_cell_value(x, cipher))
        
        # Check if decryption was successful by looking for errors in cells
        error_count = 0
        for col in decrypted_df.columns:
            for i, val in enumerate(decrypted_df[col]):
                if isinstance(val, str) and val.startswith("ERROR:"):
                    error_count += 1
        
        # Return both DataFrame and error count
        return decrypted_df, error_count
    except Exception as e:
        # In case of error, return None and error message
        return None, str(e)

# Analyze elevator camera data
@st.cache_data
def analyze_elevator_data(df):
    """
    Function to analyze elevator camera data
    and prepare specific visualizations
    """
    # Fix data format
    df['Elevator_IN'] = df['Elevator_IN'].astype(str).str.lower() == 'true'
    df['Elevator_OUT'] = df['Elevator_OUT'].astype(str).str.lower() == 'true'
    
    # Make sure dates and times are in correct format
    df['data'] = pd.to_datetime(df['data'])
    df['ora'] = pd.to_datetime(df['ora'])
    
    # Extract only date as string (YYYY-MM-DD)
    df['date_only'] = df['data'].dt.strftime('%Y-%m-%d')
    
    # 1. IN and OUT frequencies by day
    entries_per_day = df[df['Elevator_IN']].groupby('date_only').size()
    exits_per_day = df[df['Elevator_OUT']].groupby('date_only').size()
    
    # Create a combined DataFrame
    frequency_by_day = pd.DataFrame({
        'entries': entries_per_day,
        'exits': exits_per_day
    }).fillna(0).astype(int)
    
    # 2. Top 10 users with most visits
    user_frequency = df.groupby('name').size().sort_values(ascending=False).head(10)
    
    # 3. Prepare details for each user
    user_details = {}
    for user in user_frequency.index:
        user_data = df[df['name'] == user]
        
        # Registration distributions
        registrations_by_date = user_data.groupby('date_only').size()
        
        # Calculate stay durations
        stay_durations = []
        
        # Group by day
        for date, day_data in user_data.groupby('date_only'):
            # Sort by time
            day_data = day_data.sort_values('ora')
            
            # Look for IN-OUT pairs
            records = day_data.to_dict('records')
            for i in range(len(records) - 1):
                if records[i]['Elevator_IN'] and records[i+1]['Elevator_OUT']:
                    in_time = records[i]['ora']
                    out_time = records[i+1]['ora']
                    duration = (out_time - in_time).total_seconds() / 60  # in minutes
                    
                    # Save details
                    stay_durations.append({
                        'date': date,
                        'in_time': in_time.time(),
                        'out_time': out_time.time(),
                        'duration_minutes': duration
                    })
                    
                    # Skip next record
                    i += 1
        
        # Create DataFrame for stay durations
        durations_df = pd.DataFrame(stay_durations) if stay_durations else pd.DataFrame(columns=['date', 'in_time', 'out_time', 'duration_minutes'])
        
        # Calculate statistics
        avg_duration = durations_df['duration_minutes'].mean() if not durations_df.empty else 0
        entries_count = user_data[user_data['Elevator_IN']].shape[0]
        exits_count = user_data[user_data['Elevator_OUT']].shape[0]
        
        # Save user details
        user_details[user] = {
            'total_visits': len(user_data),
            'registrations_by_date': registrations_by_date,
            'stay_durations': durations_df,
            'avg_duration': round(avg_duration, 1),
            'entries_count': entries_count,
            'exits_count': exits_count
        }
    
    # 4. NEW: Find people who were together at the same time (same datetime)
    # Create a datetime column for precise matching - ensure we have exact time matching
    df['datetime'] = pd.to_datetime(df['data'].dt.strftime('%Y-%m-%d') + ' ' + df['ora'].dt.strftime('%H:%M:%S'))
    
    # First group by datetime to find instances where multiple people were recorded at exactly the same time
    datetime_groups = df.groupby('datetime')
    
    # Then for each datetime, separate by IN and OUT to find people who were together for the same operation
    cooccurrences = []
    
    for dt, group in datetime_groups:
        # First check for people entering together (Elevator_IN)
        in_group = group[group['Elevator_IN'] == True]
        if len(in_group) > 1:  # More than one person entering at the same time
            people_list = in_group['name'].tolist()
            cooccurrences.append({
                'datetime': dt,
                'date': dt.strftime('%Y-%m-%d'),
                'time': dt.strftime('%H:%M:%S'),
                'people': people_list,
                'count': len(people_list),
                'direction': 'IN'
            })
        
        # Then check for people exiting together (Elevator_OUT)
        out_group = group[group['Elevator_OUT'] == True]
        if len(out_group) > 1:  # More than one person exiting at the same time
            people_list = out_group['name'].tolist()
            cooccurrences.append({
                'datetime': dt,
                'date': dt.strftime('%Y-%m-%d'),
                'time': dt.strftime('%H:%M:%S'),
                'people': people_list,
                'count': len(people_list),
                'direction': 'OUT'
            })
    
    # Create DataFrame of co-occurrences
    cooccurrences_df = pd.DataFrame(cooccurrences) if cooccurrences else pd.DataFrame(
        columns=['datetime', 'date', 'time', 'people', 'count', 'direction'])
    
    # Generate frequency counts for each pair of people being together
    all_pairs = []
    if not cooccurrences_df.empty:
        for idx, row in cooccurrences_df.iterrows():
            people_list = row['people']
            # Generate all possible pairs from the people in this group
            for i in range(len(people_list)):
                for j in range(i+1, len(people_list)):
                    all_pairs.append({
                        'person1': people_list[i],
                        'person2': people_list[j],
                        'datetime': row['datetime'],
                        'date': row['date'],
                        'time': row['time'],
                        'direction': row['direction']
                    })
    
    pairs_df = pd.DataFrame(all_pairs) if all_pairs else pd.DataFrame(
        columns=['person1', 'person2', 'datetime', 'date', 'time', 'direction'])
    
    # 5. NEW: Find sequence anomalies (OUT without subsequent IN and IN without previous OUT)
    sequence_anomalies = []
    unique_persons = df['name'].unique()
    
    for person in unique_persons:
        person_data = df[df['name'] == person].copy()
        
        # Sort by datetime for proper sequence analysis
        person_data = person_data.sort_values('datetime')
        
        # Convert to list of records for easier processing
        records = person_data.to_dict('records')
        
        # Skip if no records
        if not records:
            continue
        
        # Process first record - check if it's an IN without previous OUT
        first_record = records[0]
        first_action = 'IN' if first_record['Elevator_IN'] else 'OUT' if first_record['Elevator_OUT'] else 'UNKNOWN'
        
        if first_action == 'IN':
            # First action is IN - this is normal for the first record
            last_action = 'IN'
        elif first_action == 'OUT':
            # First action is OUT - this is normal (the person might have entered before monitoring started)
            last_action = 'OUT'
        else:
            # Unknown action - skip
            last_action = None
        
        # Process each subsequent record to find anomalies
        for i in range(1, len(records)):
            current_record = records[i]
            current_action = 'IN' if current_record['Elevator_IN'] else 'OUT' if current_record['Elevator_OUT'] else 'UNKNOWN'
            
            # Skip unknown actions
            if current_action == 'UNKNOWN':
                continue
                
            # Check for anomalies
            if current_action == 'IN' and last_action == 'IN':
                # IN without previous OUT - someone entered twice without exiting
                sequence_anomalies.append({
                    'person': person,
                    'datetime': current_record['datetime'],
                    'date': current_record['datetime'].strftime('%Y-%m-%d'),
                    'time': current_record['datetime'].strftime('%H:%M:%S'),
                    'action': current_action,
                    'last_action': last_action,
                    'anomaly_type': 'IN without previous OUT'
                })
            elif current_action == 'OUT' and last_action == 'OUT':
                # OUT without subsequent IN - someone exited twice without entering between
                sequence_anomalies.append({
                    'person': person,
                    'datetime': records[i-1]['datetime'],  # The previous OUT record
                    'date': records[i-1]['datetime'].strftime('%Y-%m-%d'),
                    'time': records[i-1]['datetime'].strftime('%H:%M:%S'),
                    'action': last_action,
                    'next_action': current_action,
                    'anomaly_type': 'OUT without subsequent IN'
                })
            
            # Update last action
            last_action = current_action
        
        # Check the last record for an unmatched OUT
        if len(records) > 0 and last_action == 'OUT':
            # Last action is OUT - this is normal (the person might not have returned yet)
            pass
    
    # Create DataFrame for sequence anomalies
    anomalies_df = pd.DataFrame(sequence_anomalies) if sequence_anomalies else pd.DataFrame(
        columns=['person', 'datetime', 'date', 'time', 'action', 'expected', 'anomaly_type'])
    
    return {
        'frequency_by_day': frequency_by_day,
        'user_frequency': user_frequency,
        'user_details': user_details,
        'cooccurrences': cooccurrences_df,
        'pairs': pairs_df,
        'anomalies': anomalies_df  # New result with sequence anomalies
    }

# Disable menu in sidebar
st.set_page_config(
    page_title="Detective Tool", 
    page_icon="🔐",
    layout="wide",
    initial_sidebar_state="collapsed"
)

# Hide sidebar completely
st.markdown(
    """
    <style>
    #MainMenu {visibility: hidden;}
    .css-1rs6os {visibility: hidden;}
    .css-17ziqus {visibility: hidden;}
    </style>
    """,
    unsafe_allow_html=True,
)

# Initialize session state for decrypted data
if 'decrypted_data' not in st.session_state:
    st.session_state.decrypted_data = None
if 'decryption_done' not in st.session_state:
    st.session_state.decryption_done = False
if 'analysis_results' not in st.session_state:
    st.session_state.analysis_results = None
if 'selected_user' not in st.session_state:
    st.session_state.selected_user = None

# Title and description
st.title("🔐 Detective Tool")
st.write("""
This application allows you to upload an Excel file with encrypted elevator camera data
and view the original data using the correct password.
""")

# File upload and password
uploaded_file = st.file_uploader("Upload an encrypted Excel file", type=["xlsx", "xls"], 
                               key="file_uploader")
password = st.text_input("Enter decryption password", type="password", 
                        key="password_input")

# Function to handle decryption
def decrypt_data():
    try:
        # Read Excel file
        encrypted_df = pd.read_excel(st.session_state.file_uploader)
        # Convert DataFrame to JSON for caching
        encrypted_df_json = encrypted_df.to_json()
        
        # Decrypt using cached function
        decrypted_df, error_info = decrypt_dataframe_cached(encrypted_df_json, st.session_state.password_input)
        
        if decrypted_df is not None:
            # Save decrypted data in session state
            st.session_state.decrypted_data = decrypted_df
            st.session_state.decryption_done = True
            
            # Analyze data for specific visualizations
            st.session_state.analysis_results = analyze_elevator_data(decrypted_df)
            
            if isinstance(error_info, int) and error_info > 0:
                st.warning(f"Found {error_info} decryption errors. The password might be incorrect.")
        else:
            st.error(f"Error during decryption: {error_info}")
            st.session_state.decryption_done = False
    except Exception as e:
        st.error("WRONG PASSWORD")
        st.session_state.decryption_done = False

# Button to start decryption
if uploaded_file is not None and password and not st.session_state.decryption_done:
    if st.button("View Decrypted Data"):
        with st.spinner("Decryption in progress..."):
            decrypt_data()

# Display decrypted data if available
if st.session_state.decryption_done and st.session_state.decrypted_data is not None and st.session_state.analysis_results is not None:
    decrypted_df = st.session_state.decrypted_data
    analysis = st.session_state.analysis_results
    
    # Show decrypted dataframe
    st.success("Decryption completed!")
    
    # Show basic statistics
    st.subheader("Data Information")
    col1, col2, col3 = st.columns(3)
    with col1:
        st.metric("Rows", len(decrypted_df))
    with col2:
        st.metric("Unique Users", decrypted_df['name'].nunique())
    with col3:
        # Handle date format correctly
        try:
            min_date = pd.to_datetime(decrypted_df['data']).min()
            max_date = pd.to_datetime(decrypted_df['data']).max()
            date_range = f"{min_date.strftime('%Y-%m-%d')} - {max_date.strftime('%Y-%m-%d')}"
        except:
            date_range = "Available Period"
        st.metric("Period", date_range)
    
    # Display data
    with st.expander("Raw Data Preview"):
        st.dataframe(decrypted_df)
    
    # Tabs for requested visualizations
    tab1, tab2, tab3, tab4, tab5 = st.tabs([
        "IN/OUT Frequencies by Day", 
        "Top 10 Frequent Users", 
        "Individual User Details",
        "People Together",
        "Sequence Anomalies"  # New tab for anomalies
    ])
    
    # Tab 1: IN/OUT Frequencies by day
    with tab1:
        st.subheader("IN and OUT Frequencies by Day")
        
        # Prepare data for chart in a more direct format
        chart_data = analysis['frequency_by_day'].reset_index()
        chart_data = chart_data.rename(columns={'date_only': 'Date', 'entries': 'Entries', 'exits': 'Exits'})
        chart_data['Date'] = chart_data['Date'].astype(str)
        
        # Reorganize data for chart
        chart_data_melted = pd.melt(
            chart_data, 
            id_vars=['Date'], 
            value_vars=['Entries', 'Exits'],
            var_name='Type', 
            value_name='Count'
        )
        
        # Create a single chart with two types of bars
        chart = alt.Chart(chart_data_melted).mark_bar().encode(
            x='Date:N',
            y='Count:Q',
            color=alt.Color('Type:N', scale=alt.Scale(domain=['Entries', 'Exits'], 
                                                    range=['#5276A7', '#57A44C'])),
            tooltip=['Date', 'Type', 'Count']
        ).properties(
            width=700,
            height=400,
            title='Entry (blue) and Exit (green) frequencies by day'
        )
        
        st.altair_chart(chart, use_container_width=True)
        
        # Show data in table format
        st.write("Data in table format:")
        st.dataframe(chart_data)
    
    # Tab 2: Top 10 frequent users
    with tab2:
        st.subheader("Top 10 Most Frequent Users")
        
        # Prepare data for chart
        chart_data = analysis['user_frequency'].reset_index()
        chart_data.columns = ['User', 'Frequency']
        
        # Create bar chart
        chart = alt.Chart(chart_data).mark_bar().encode(
            x=alt.X('Frequency:Q', title='Number of registrations'),
            y=alt.Y('User:N', title='', sort='-x'),
            color=alt.Color('Frequency:Q', scale=alt.Scale(scheme='blues')),
            tooltip=['User', 'Frequency']
        ).properties(
            width=700,
            height=400,
            title='Top 10 users by number of registrations'
        )
        
        st.altair_chart(chart, use_container_width=True)
        
        # Show data in table format
        st.write("Data in table format:")
        st.dataframe(chart_data)
    
    # Tab 3: Individual user details
    with tab3:
        st.subheader("Individual User Details")
        
        # User selector
        user_list = list(analysis['user_frequency'].index)
        
        # If no user is already selected, take the first from the list
        if st.session_state.selected_user is None and user_list:
            st.session_state.selected_user = user_list[0]
        
        # Widget to select user
        selected_user = st.selectbox(
            "Select a user:",
            options=user_list,
            index=user_list.index(st.session_state.selected_user) if st.session_state.selected_user in user_list else 0
        )
        
        # Update session state
        st.session_state.selected_user = selected_user
        
        if selected_user:
            user_data = analysis['user_details'][selected_user]
            
            # Show general statistics
            col1, col2, col3, col4 = st.columns(4)
            with col1:
                st.metric("Total Registrations", user_data['total_visits'])
            with col2:
                st.metric("Entries", user_data['entries_count'])
            with col3:
                st.metric("Exits", user_data['exits_count'])
            with col4:
                st.metric("Average Time (min)", user_data['avg_duration'])
            
            # 1. Registration distribution over time
            st.subheader("Registration Distribution")
            
            if not user_data['registrations_by_date'].empty:
                # Prepare data for chart
                reg_data = user_data['registrations_by_date'].reset_index()
                reg_data.columns = ['Date', 'Count']
                reg_data['Date'] = reg_data['Date'].astype(str)
                
                # Create chart
                chart = alt.Chart(reg_data).mark_bar().encode(
                    x=alt.X('Date:N', title='Date'),
                    y=alt.Y('Count:Q', title='Number of registrations'),
                    color=alt.Color('Count:Q', scale=alt.Scale(scheme='blues')),
                    tooltip=['Date', 'Count']
                ).properties(
                    width=700,
                    height=300,
                    title=f'Registration distribution for {selected_user}'
                )
                
                st.altair_chart(chart, use_container_width=True)
            else:
                st.info("No registration data available for this user.")
            
            # 2. Stay duration
            st.subheader("Stay Duration")
            
            if not user_data['stay_durations'].empty:
                # Prepare data for chart
                dur_data = user_data['stay_durations'].copy()
                
                if len(dur_data) > 0:
                    # Explicitly convert the date column to datetime and then to formatted string
                    dur_data['date'] = pd.to_datetime(dur_data['date']).dt.strftime('%Y-%m-%d')
                    
                    # Rename columns
                    dur_data.columns = ['Date', 'Entry Time', 'Exit Time', 'Duration (min)']
                    
                    # Use nominal field for dates
                    chart = alt.Chart(dur_data).mark_circle(size=100).encode(
                        x=alt.X('Date:N', title='Date', sort=None),  # Use nominal type and maintain date order
                        y=alt.Y('Duration (min):Q', title='Duration (minutes)'),
                        size=alt.Size('Duration (min):Q', legend=None),
                        color=alt.Color('Duration (min):Q', scale=alt.Scale(scheme='viridis')),
                        tooltip=['Date', 'Entry Time', 'Exit Time', 'Duration (min)']
                    ).properties(
                        width=700,
                        height=300,
                        title=f'Stay durations for {selected_user}'
                    )
                    
                    st.altair_chart(chart, use_container_width=True)
                    
                    # Show data in table format
                    st.write("Stay duration details:")
                    st.dataframe(dur_data)
                else:
                    st.info("No stay duration recorded for this user.")
            else:
                st.info("No stay duration data available for this user.")
    
    # Tab 4: NEW - People who were together
    with tab4:
        st.subheader("People Detected Together")
        
        # Get co-occurrence data
        cooccurrences_df = analysis['cooccurrences']
        pairs_df = analysis['pairs']
        
        if not cooccurrences_df.empty:
            # Show summary metrics
            col1, col2, col3 = st.columns(3)
            with col1:
                st.metric("Total Group Detections", len(cooccurrences_df))
            with col2:
                st.metric("Maximum Group Size", cooccurrences_df['count'].max())
            with col3:
                unique_pairs = len(pairs_df.groupby(['person1', 'person2']))
                st.metric("Unique Pairs", unique_pairs)
            
            # Main view: All groups detected together
            st.subheader("All Group Detections")
            
            # Format data for display
            display_df = cooccurrences_df.copy()
            display_df['people_list'] = display_df['people'].apply(lambda x: ", ".join(x))
            display_df = display_df[['date', 'time', 'people_list', 'count', 'direction']]
            display_df = display_df.sort_values(['date', 'time'])
            display_df.columns = ['Date', 'Time', 'People', 'Group Size', 'Direction']
            
            # Add filters
            st.write("Filter results:")
            col1, col2 = st.columns(2)
            with col1:
                min_group_size = st.number_input("Minimum group size:", min_value=2, max_value=int(cooccurrences_df['count'].max()), value=2)
            with col2:
                direction_filter = st.radio("Direction:", options=["All", "IN", "OUT"], horizontal=True)
            
            # Apply filters
            filtered_df = display_df[display_df['Group Size'] >= min_group_size]
            if direction_filter != "All":
                filtered_df = filtered_df[filtered_df['Direction'] == direction_filter]
            
            st.write(f"Showing {len(filtered_df)} results out of {len(display_df)} total.")
            st.dataframe(filtered_df)
            
            # Most frequent pairs section
            if not pairs_df.empty:
                st.subheader("Most Frequent Pairs")
                
                # Count frequency of each pair
                pair_counts = pairs_df.groupby(['person1', 'person2']).size().reset_index(name='frequency')
                pair_counts = pair_counts.sort_values('frequency', ascending=False)
                
                # Create a readable pair name
                pair_counts['pair'] = pair_counts.apply(lambda x: f"{x['person1']} & {x['person2']}", axis=1)
                
                # Display top 15 pairs
                top_pairs = pair_counts.head(15)
                
                # Create chart
                chart = alt.Chart(top_pairs).mark_bar().encode(
                    x=alt.X('frequency:Q', title='Times seen together'),
                    y=alt.Y('pair:N', title='', sort='-x'),
                    tooltip=['pair', 'frequency']
                ).properties(
                    width=700,
                    height=400,
                    title='Most frequently seen together'
                )
                
                st.altair_chart(chart, use_container_width=True)
                
                # Explore specific pairs
                st.subheader("Explore a Specific Pair")
                
                pair_options = pair_counts['pair'].tolist()
                selected_pair = st.selectbox("Select a pair to see details:", pair_options)
                
                if selected_pair:
                    person1, person2 = selected_pair.split(" & ")
                    
                    # Filter data for this pair
                    pair_instances = pairs_df[
                        ((pairs_df['person1'] == person1) & (pairs_df['person2'] == person2)) | 
                        ((pairs_df['person1'] == person2) & (pairs_df['person2'] == person1))
                    ]
                    
                    # Create a readable version for display
                    display_data = pair_instances[['date', 'time', 'direction']].copy()
                    display_data = display_data.sort_values('date')
                    display_data.columns = ['Date', 'Time', 'Direction']
                    
                    st.write(f"All {len(display_data)} instances when {selected_pair} were together:")
                    st.dataframe(display_data)
                    
                    # Summary of movement patterns
                    movement_summary = display_data['Direction'].value_counts().reset_index()
                    movement_summary.columns = ['Direction', 'Count']
                    
                    if len(movement_summary) > 0:
                        # Create pie chart of directions
                        chart = alt.Chart(movement_summary).mark_arc().encode(
                            theta=alt.Theta(field="Count", type="quantitative"),
                            color=alt.Color(field="Direction", type="nominal", 
                                           scale=alt.Scale(domain=['IN', 'OUT'], 
                                                          range=['#5276A7', '#57A44C'])),
                            tooltip=['Direction', 'Count']
                        ).properties(
                            width=300,
                            height=300,
                            title=f'Movement patterns of {selected_pair}'
                        )
                        
                        st.altair_chart(chart)
                
                # User search functionality
                st.subheader("Search for a Person")
                search_person = st.text_input("Enter a person's name:")
                
                if search_person:
                    # Find all pairs involving this person
                    person_pairs = pairs_df[
                        (pairs_df['person1'] == search_person) | 
                        (pairs_df['person2'] == search_person)
                    ]
                    
                    if len(person_pairs) > 0:
                        # Get list of people this person was with
                        companions = []
                        for _, row in person_pairs.iterrows():
                            if row['person1'] == search_person:
                                companions.append(row['person2'])
                            else:
                                companions.append(row['person1'])
                        
                        # Count frequency of each companion
                        companion_counts = pd.Series(companions).value_counts().reset_index()
                        companion_counts.columns = ['Person', 'Times together']
                        
                        st.write(f"{search_person} was detected with {len(companion_counts)} different people:")
                        st.dataframe(companion_counts)
                    else:
                        st.info(f"{search_person} was never detected with other people.")
            else:
                st.info("No pairs data available.")
        else:
            st.info("No instances found where multiple people were detected at the same time.")
    
    # Tab 5: NEW - Sequence Anomalies
    with tab5:
        st.subheader("Sequence Anomalies")
        st.write("""
        This tab shows two types of sequence anomalies:
        1. **IN without previous OUT**: People who entered the elevator without having exited before
        2. **OUT without subsequent IN**: People who exited the elevator but never came back in
        
        These anomalies might indicate unusual behavior, gaps in monitoring, or issues with the detection system.
        """)
        
        # Get anomalies data
        anomalies_df = analysis['anomalies']
        
        if not anomalies_df.empty:
            # Show summary statistics
            col1, col2, col3 = st.columns(3)
            with col1:
                st.metric("Total Anomalies", len(anomalies_df))
            with col2:
                st.metric("People with Anomalies", anomalies_df['person'].nunique())
            with col3:
                # Count by anomaly type
                anomaly_counts = anomalies_df['anomaly_type'].value_counts()
                in_without_out = anomaly_counts.get('IN without previous OUT', 0)
                out_without_in = anomaly_counts.get('OUT without subsequent IN', 0)
                
                if in_without_out > out_without_in:
                    most_common = "IN without previous OUT"
                else:
                    most_common = "OUT without subsequent IN"
                
                st.metric("Most Common Type", most_common)
            
            # Add filters
            st.write("Filter results:")
            col1, col2 = st.columns(2)
            with col1:
                anomaly_type_filter = st.radio(
                    "Anomaly type:", 
                    options=["All", "IN without previous OUT", "OUT without subsequent IN"],
                    horizontal=True
                )
            with col2:
                search_person = st.text_input("Search for specific person:")
            
            # Apply filters
            filtered_df = anomalies_df.copy()
            
            if anomaly_type_filter == "IN without previous OUT":
                filtered_df = filtered_df[filtered_df['anomaly_type'] == 'IN without previous OUT']
            elif anomaly_type_filter == "OUT without subsequent IN":
                filtered_df = filtered_df[filtered_df['anomaly_type'] == 'OUT without subsequent IN']
                
            if search_person:
                filtered_df = filtered_df[filtered_df['person'].str.contains(search_person, case=False)]
            
            # Create display dataframe, handle different column structures
            cols_to_display = ['person', 'date', 'time', 'anomaly_type']
            if 'action' in filtered_df.columns:
                cols_to_display.append('action')
            if 'last_action' in filtered_df.columns:
                cols_to_display.append('last_action')
            if 'next_action' in filtered_df.columns:
                cols_to_display.append('next_action')
            
            display_df = filtered_df[cols_to_display].copy()
            # Rename columns based on which ones are present
            column_mapping = {
                'person': 'Person',
                'date': 'Date',
                'time': 'Time',
                'anomaly_type': 'Anomaly Type',
                'action': 'Action',
                'last_action': 'Previous Action',
                'next_action': 'Next Action'
            }
            
            display_df.columns = [column_mapping.get(col, col) for col in display_df.columns]
            
            # Sort by person and datetime
            display_df = display_df.sort_values(['Person', 'Date', 'Time'])
            
            # Show results
            st.write(f"Showing {len(display_df)} results out of {len(anomalies_df)} total.")
            st.dataframe(display_df)
            
            # Summary by person
            st.subheader("Summary by Person")
            
            # Count anomalies by person
            person_counts = anomalies_df.groupby('person').size().reset_index(name='count')
            person_counts = person_counts.sort_values('count', ascending=False)
            
            # Show top 15 people with most anomalies
            if len(person_counts) > 0:
                top_anomalies = person_counts.head(15)
                
                # Create chart
                chart = alt.Chart(top_anomalies).mark_bar().encode(
                    x=alt.X('count:Q', title='Number of anomalies'),
                    y=alt.Y('person:N', title='', sort='-x'),
                    tooltip=['person', 'count']
                ).properties(
                    width=700,
                    height=400,
                    title='People with most sequence anomalies'
                )
                
                st.altair_chart(chart, use_container_width=True)
                
                # Add details for specific person
                st.subheader("Details by Person")
                person_list = person_counts['person'].tolist()
                selected_person = st.selectbox("Select a person:", person_list)
                
                if selected_person:
                    # Get anomalies for selected person
                    person_anomalies = anomalies_df[anomalies_df['person'] == selected_person]
                    
                    # Determine which columns to display
                    display_cols = ['date', 'time', 'anomaly_type']
                    if 'action' in person_anomalies.columns:
                        display_cols.append('action')
                    if 'last_action' in person_anomalies.columns:
                        display_cols.append('last_action')
                    if 'next_action' in person_anomalies.columns:
                        display_cols.append('next_action')
                    
                    person_display = person_anomalies[display_cols].copy()
                    
                    # Set proper column names
                    column_mapping = {
                        'date': 'Date',
                        'time': 'Time',
                        'anomaly_type': 'Anomaly Type',
                        'action': 'Action',
                        'last_action': 'Previous Action',
                        'next_action': 'Next Action'
                    }
                    
                    person_display.columns = [column_mapping[col] for col in display_cols]
                    
                    # Sort by date and time
                    person_display = person_display.sort_values(['Date', 'Time'])
                    
                    # Show table
                    st.write(f"Anomalies detected for {selected_person}:")
                    st.dataframe(person_display)
                    
                    # Show summary by type
                    anomaly_types = person_anomalies['anomaly_type'].value_counts().reset_index()
                    anomaly_types.columns = ['Type', 'Count']
                    
                    # Create chart
                    pie = alt.Chart(anomaly_types).mark_arc().encode(
                        theta=alt.Theta(field="Count", type="quantitative"),
                        color=alt.Color(field="Type", type="nominal"),
                        tooltip=['Type', 'Count']
                    ).properties(
                        width=300,
                        height=300,
                        title=f'Anomaly types for {selected_person}'
                    )
                    
                    st.altair_chart(pie)
        else:
            st.info("No sequence anomalies detected in the data.")

# Button to reset view
if st.session_state.decryption_done:
    if st.button("Load another file"):
        # Reset session state
        st.session_state.decrypted_data = None
        st.session_state.decryption_done = False
        st.session_state.analysis_results = None
        st.session_state.selected_user = None
        # Force page refresh
        st.rerun()

# Footer notes
st.markdown("---")
st.caption("""
**Note:** Data can only be viewed in this application and cannot be exported.
""")