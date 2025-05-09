from models import Application, PatchHistory
from sqlalchemy.orm import Session


def get_all_apps(db: Session):
    apps=db.query(Application).all()
    return [
        {
            "app_name": app.app_name,
            "app_id": app.app_id,
            "current_version": app.current_version,
            "available_update": app.available_update
        }
        for app in apps
    ]

def get_patch_info(db: Session, app_id):
    patches = db.query(PatchHistory).filter(PatchHistory.app_id == app_id).all()
    return [
        {
            "app_id": patch.app_id,
            "history_id": patch.history_id,
            "patch_version": patch.patch_version
        }
        for patch in patches
    ]
    




# print(get_all_apps())

# def get_patch_info(db: Session, app_id):
#     patches = db.query(PatchHistory).all()
#     for patch in patches:
#         if app_id== patches.app_id:
#             return [
#                 {
#                     "app_id": patches.app_id,
#                     "History_id": patches.history_id,
#                     "patch_version": patches.patch_version
#                 }
#             ]


# def update_patch_severity(db:Session, patch_id : int, new_severity : str):
#     patches = db.query(PatchHistory).all()
#     for patch in patches:
#         if patch_id==patch.patch_id:
#             patch.severity = new_severity
#             db.commit()
#             db.refresh(patch)
#             return patch
#         else:
#             return None










