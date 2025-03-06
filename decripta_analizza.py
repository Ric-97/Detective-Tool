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
    
    return {
        'frequency_by_day': frequency_by_day,
        'user_frequency': user_frequency,
        'user_details': user_details
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
        st.error(f"An error occurred: {str(e)}")
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
    tab1, tab2, tab3 = st.tabs([
        "IN/OUT Frequencies by Day", 
        "Top 10 Frequent Users", 
        "Individual User Details"
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