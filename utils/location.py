def get_indian_states():
    """
    Get list of Indian states and union territories
    """
    return [
        "Andhra Pradesh",
        "Arunachal Pradesh", 
        "Assam",
        "Bihar",
        "Chhattisgarh",
        "Goa",
        "Gujarat",
        "Haryana",
        "Himachal Pradesh",
        "Jharkhand",
        "Karnataka",
        "Kerala",
        "Madhya Pradesh",
        "Maharashtra",
        "Manipur",
        "Meghalaya",
        "Mizoram",
        "Nagaland",
        "Odisha",
        "Punjab",
        "Rajasthan",
        "Sikkim",
        "Tamil Nadu",
        "Telangana",
        "Tripura",
        "Uttar Pradesh",
        "Uttarakhand",
        "West Bengal",
        "Andaman and Nicobar Islands",
        "Chandigarh",
        "Dadra and Nagar Haveli and Daman and Diu",
        "Delhi",
        "Jammu and Kashmir",
        "Ladakh",
        "Lakshadweep",
        "Puducherry"
    ]

def find_volunteers_by_location(state, district=None):
    """
    Find volunteers by state and optionally district
    """
    from models.database import db
    
    conn = db.get_connection()
    cursor = conn.cursor()
    
    query = '''
        SELECT id, full_name, email, state, district
        FROM users 
        WHERE user_type = 'volunteer' 
        AND verification_status = 'approved'
        AND is_verified = TRUE
        AND state = ?
    '''
    params = [state]
    
    if district:
        query += ' AND district = ?'
        params.append(district)
    
    cursor.execute(query, params)
    volunteers = cursor.fetchall()
    
    conn.close()
    return [dict(volunteer) for volunteer in volunteers]

def match_volunteers_to_request(request_id):
    """
    Find volunteers that match the skills required for an emergency request
    and are in the same state/district
    """
    from models.database import db
    
    conn = db.get_connection()
    cursor = conn.cursor()
    
    # Get request details and required skills
    cursor.execute('''
        SELECT er.*, GROUP_CONCAT(s.name) as required_skills, GROUP_CONCAT(rs.skill_id) as skill_ids
        FROM emergency_requests er
        LEFT JOIN request_skills rs ON er.id = rs.request_id
        LEFT JOIN skills s ON rs.skill_id = s.id
        WHERE er.id = ?
        GROUP BY er.id
    ''', (request_id,))
    
    request = cursor.fetchone()
    if not request:
        return []
    
    # Get volunteers in the same state with matching skills
    if request['skill_ids']:
        skill_ids = request['skill_ids'].split(',')
        placeholders = ','.join(['?' for _ in skill_ids])
        
        cursor.execute(f'''
            SELECT DISTINCT u.id, u.full_name, u.email, u.state, u.district,
                   GROUP_CONCAT(s.name) as volunteer_skills,
                   GROUP_CONCAT(us.proficiency_level) as proficiency_levels
            FROM users u
            JOIN user_skills us ON u.id = us.user_id
            JOIN skills s ON us.skill_id = s.id
            WHERE s.id IN ({placeholders})
            AND u.user_type = 'volunteer'
            AND u.verification_status = 'approved'
            AND u.is_verified = TRUE
            AND us.is_verified = TRUE
            AND u.state = ?
            GROUP BY u.id
            ORDER BY u.district = ? DESC, u.full_name
        ''', skill_ids + [request['state'], request['district']])
    else:
        # If no specific skills required, get all volunteers in the area
        cursor.execute('''
            SELECT u.id, u.full_name, u.email, u.state, u.district,
                   '' as volunteer_skills, '' as proficiency_levels
            FROM users u
            WHERE u.user_type = 'volunteer'
            AND u.verification_status = 'approved'
            AND u.is_verified = TRUE
            AND u.state = ?
            ORDER BY u.district = ? DESC, u.full_name
        ''', (request['state'], request['district']))
    
    volunteers = cursor.fetchall()
    
    # Format the results
    matched_volunteers = []
    for volunteer in volunteers:
        matched_volunteers.append({
            'id': volunteer['id'],
            'full_name': volunteer['full_name'],
            'email': volunteer['email'],
            'state': volunteer['state'],
            'district': volunteer['district'],
            'skills': volunteer['volunteer_skills'].split(',') if volunteer['volunteer_skills'] else [],
            'proficiency_levels': volunteer['proficiency_levels'].split(',') if volunteer['proficiency_levels'] else [],
            'location_match': volunteer['district'] == request['district']
        })
    
    conn.close()
    return matched_volunteers