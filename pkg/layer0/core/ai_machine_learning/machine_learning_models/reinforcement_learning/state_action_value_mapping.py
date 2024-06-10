class StateActionValueMapping:
    def __init__(self):
        # Initialize state-action-value mapping and any necessary variables or parameters
        self.state_action_values = {}

    def update_state_action_value(self, state, action, reward, next_state, alpha, gamma):
        """
        Update state-action value based on observed reward and transition to next state.

        Args:
            state (str): Current state.
            action (str): Action taken in the current state.
            reward (float): Reward received for taking the action.
            next_state (str): Next state after taking the action.
            alpha (float): Learning rate.
            gamma (float): Discount factor for future rewards.

        Returns:
            None
        """
        if state not in self.state_action_values:
            self.state_action_values[state] = {}

        if next_state not in self.state_action_values:
            self.state_action_values[next_state] = {}

        # Update state-action value based on reward and next state
        current_value = self.state_action_values[state].get(action, 0.0)
        next_max_value = max(self.state_action_values[next_state].values(), default=0.0)
        updated_value = current_value + alpha * (reward + gamma * next_max_value - current_value)
        self.state_action_values[state][action] = updated_value

    def get_optimal_action(self, state):
        """
        Get the optimal action for a given state based on the learned state-action values.

        Args:
            state (str): Current state.

        Returns:
            str: Optimal action for the given state.
        """
        if state not in self.state_action_values:
            return None

        optimal_action = max(self.state_action_values[state], key=self.state_action_values[state].get)
        return optimal_action

    # Add more methods as needed for additional functionalities

# Example usage:
state_action_mapper = StateActionValueMapping()

# Example updating state-action values
state_action_mapper.update_state_action_value('state1', 'action1', 10.0, 'state2', 0.1, 0.9)

# Example getting optimal action for a state
optimal_action = state_action_mapper.get_optimal_action('state1')
print("Optimal action for state1:", optimal_action)
