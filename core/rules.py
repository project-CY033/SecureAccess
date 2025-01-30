class RuleManager:
    def __init__(self, config, main_window):
        self.rules = config['custom_rules']
        self.config = config
        self.main_window = main_window
    def add_rule(self, rule):
         self.rules.append(rule)
         self.config['custom_rules'].append(rule)
         print(f"Rule added {rule}")

    def remove_rule(self, rule):
        if rule in self.rules:
             self.rules.remove(rule)
             self.config['custom_rules'].remove(rule)
             print(f"Rule Remove {rule}")

    def match_rules(self, packet):
        for rule in self.rules:
              try:
                 if eval(rule, None, {'packet':packet}):
                    return True
              except Exception as e:
                    self.main_window.update_monitor_data(f"Error in rule evaluation {rule} : {e}")
        return False