#!/usr/bin/env python3

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from database_setup import Base, User, Category, Item

engine = create_engine('sqlite:///catalog.db')
# Bind the engine to the metadata of the Base class so that the
# declaratives can be accessed through a DBSession instance
Base.metadata.bind = engine

DBSession = sessionmaker(bind=engine)
# A DBSession() instance establishes all conversations with the database
# and represents a "staging zone" for all the objects loaded into the
# database session object. Any change made against the objects in the
# session won't be persisted into the database until you call
# session.commit(). If you're not happy about the changes, you can
# revert all of them back to the last commit by calling
# session.rollback()
session = DBSession()

#Create fake user
user1 = User(name="Drew Roberts", email="drew@gmail.com")
user2 = User(name="fokaskostas", email="kosfok1981@gmail.com")

session.add(user1)
session.commit()

#Create categories
category1 = Category(name="Soccer", user_id=1)

session.add(category1)
session.commit()

category2 = Category(name="Basketball", user_id=1)

session.add(category2)
session.commit()

category3 = Category(name="Hockey", user_id=1)

session.add(category3)
session.commit()

#Create items
item1 = Item(name="Soccer ball", description="A ball for soccer practice", category_id=1, user_id=1)

session.add(item1)
session.commit()

item2 = Item(name="Soccer shoes", description="Shoes to wear when playing football", category_id=1, user_id=1)

session.add(item2)
session.commit()

item3 = Item(name="Basket ball", description="A ball for basketball practice", category_id=2, user_id=1)

session.add(item3)
session.commit()

item4 = Item(name="Basketball shirt", description="Wear it when playing basketball", category_id=2, user_id=1)

session.add(item4)
session.commit()

item5 = Item(name="Hockey puck", description="A puck for playing hockey", category_id=3, user_id=1)

session.add(item5)
session.commit()

item6 = Item(name="Hockey shirt", description="Wear it when playing hockey", category_id=3, user_id=1)

session.add(item6)
session.commit()

print ("added items!")







