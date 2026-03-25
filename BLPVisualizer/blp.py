# Bell-LaPadula (BLP) Logic

LEVELS = {"U": 0, "C": 1, "S": 2, "TS": 3}

def level_val(lvl):
    return LEVELS[lvl]

class BLPSystem:
    def __init__(self):
        self.subjects = {}  
        self.objects = {}   

    def add_subject(self, name, start, max_level):
        if level_val(start) > level_val(max_level):
            print(f"  [ERROR] Cannot add {name}: start {start} > max {max_level}")
            return False
        self.subjects[name] = {"current": start, "start": start, "max": max_level}
        return True

    def add_object(self, name, level):
        self.objects[name] = level

    def validate_levels(self, subject_name, object_name):
       return self.subjects[subject_name]["current"] == self.objects[object_name]

    def set_level(self, subject_name, new_level):
        s = self.subjects[subject_name]
        cur = level_val(s["current"])
        new = level_val(new_level)
        mx  = level_val(s["max"])

        print(f"> Action: {subject_name} SET_LEVEL to {new_level}...")
        if new < cur:
            print(f"> DENY: Cannot lower level from {s['current']} to {new_level}.")
            return False
        if new > mx:
            print(f"> DENY: {new_level} exceeds max clearance ({s['max']}).")
            return False

        print(f"> ALLOW: Level raised to {new_level}.")
        s["current"] = new_level
        return True

    def read(self, subject_name, object_name):
        s   = self.subjects[subject_name]
        obj_level = self.objects[object_name]
        cur = level_val(s["current"])
        mx  = level_val(s["max"])
        obj = level_val(obj_level)

        print(f"> Action: {subject_name} READ {object_name}...")

        if cur >= obj:
            print(f"> ALLOW: Subj Lvl ({s['current']}) >= Obj Lvl ({obj_level}).")
            return True

        if obj <= mx:
            old = s["current"]
            s["current"] = obj_level
            print(f"> ALLOW: Obj Lvl ({obj_level}) <= Subj Max ({s['max']}).")
            print(f"> INFO: Raising {subject_name}'s current level to {obj_level}.")
            return True
 
        print(f"> DENY: No Read Up. Obj Lvl ({obj_level}) > Subj Max ({s['max']}).")
        return False
 
    def write(self, subject_name, object_name):
        s = self.subjects[subject_name]
        obj_level = self.objects[object_name]
        cur = level_val(s["current"])
        obj = level_val(obj_level)

        print(f"> Action: {subject_name} WRITE to {object_name}...")

        if cur <= obj:
            print(f"> ALLOW: Subj Lvl ({s['current']}) <= Obj Lvl ({obj_level}).")
            return True

        print(f"> DENY: No Write Down. Subj Lvl ({s['current']}) > Obj Lvl ({obj_level}).")
        return False

    def print_state(self):
        print("---- Current BLP State ----")
        for name, s in self.subjects.items():
            print(f"[Subject] {name}: Curr={s['current']}, Max={s['max']}")
        for name, lvl in self.objects.items():
            print(f"[Object]  {name}: Lvl={lvl}")
        print("-" * 28)
