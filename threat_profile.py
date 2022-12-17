"""
This module is for generating threat profiles according to the OCTAVE-S
risk analysis framework

"""
import json
import os
import glob
import graphviz

def generate_threat_profile(threat_data,analysis):
    """
    generate_threat_profile is a method that builds threat potfiles using graphviz library.
    The threat profiles
    are based on OCTAVE-S framework.
    """
    graph = graphviz.Digraph()

    # Threat Profile PI score = sum of PI scores of each threat in a threat profile
    tp_pi_score = 0

    # Iterate over the threat_profile dictionary and add graph nodes according to
    # the properties defined in OCTAVE-S (Asset,Access, Actors, Motives, Outcomes);
    # Access and Motives are optional.

    # Add Actors
    if threat_data["Actors"]:
        for actor in threat_data['Actors']:
            graph.node(actor, shape="oval",
                        color="violet", style="filled")

            # Add Access if present (Optional)
            if threat_data['Access']:
                graph.node(threat_data['Access'], shape="oval", color="lightblue", style="filled")
                graph.edge(threat_data['Access'], actor)

    # Add Motives if present (Optional)
    if threat_data["Motives"]:
        for motive in threat_data['Motives']:
            graph.node(motive, shape="oval",
                        color="pink", style="filled")
            probability = 0
            for actor in threat_data['Actors']:
                # If actor and motive combination is impossible break the loop,
                # otherwise connect actors with the motives
                for i in range(len(threat_data['Impossible'])):
                    if actor in threat_data['Impossible'][i] and\
                            motive in threat_data['Impossible'][i]:
                        break

                    probability = threat_data['Actors'][actor]['Probability'] +\
                        threat_data['Motives'][motive]['Probability']
                    graph.edge(
                        actor, motive, label=str(probability))
                    # Connect motives to outcomes
                    if threat_data['Outcomes'] and threat_data['Motives']:
                        for outcome in threat_data['Outcomes']:
                            graph.node(
                                outcome, shape="oval", color="orangered", style="filled")
                            # Calculate the PI (Probability * Impact) score
                            p_i = probability * \
                                threat_data['Outcomes'][outcome]['Impact']

                            graph.edge(motive, outcome,
                                        label=str(p_i))

                            tp_pi_score += p_i

    # If there are no motives, connect actors to outcomes directly
    if threat_data['Motives'] == {}:

        for actor in threat_data['Actors']:

            for outcome in threat_data['Outcomes']:
                graph.node(outcome, shape="oval",
                            color="orangered", style="filled")
                p_i = threat_data['Actors'][actor]['Probability'] *\
                    threat_data['Outcomes'][outcome]['Impact']
                graph.edge(actor, outcome, label=str(
                    p_i))

                tp_pi_score += p_i

    # The title of the threat profile
    title = threat_data['Name'] + "'s" + " Threat Profile"
    # Add title to the threat profile and make the orientation Left to Right
    graph.graph_attr = {'rankdir': 'LR',
                     'label': title + "\n" + analysis +
                      "\nTotal Threat Profile PI=" + str(tp_pi_score),
                      'labelloc': 't'}

    print(threat_data['Name'] + "PI score", tp_pi_score)
    return graph,tp_pi_score

# Open threats_data json file and convert to python dictionary
print(os.getcwd())
for json_file in list(glob.glob('Data/*.json')):
    with open(json_file, encoding="UTF-8") as f:
        threats_data = json.load(f)

    # Sum of all threat profiles PIs
    total_pi_score = 0
    foldername="Output/" + threats_data['Project'] + "/" +threats_data['Analysis']

    # Iterate over each threat information and generate threat profiles and calculate PI scores
    for record in threats_data['Assets']:
        threat_profile = generate_threat_profile(record,threats_data['Analysis'])
        filename=foldername + "/" + record['Name']
        threat_profile[0].render(filename, format='pdf', view=True)
        os.remove(filename)
        total_pi_score +=  threat_profile[1]

    # Output the total PI score for each analysis to a text file
    with open(foldername + "/" +'Total PI score.txt','w',encoding="UTF-8") as f:
        f.write(str(total_pi_score))
        