using System;
using System.Collections.Generic;
using System.Linq;

namespace CodeCake
{
    /// <summary>
    /// Contain multiple projects.
    /// </summary>
    public class YarnProjectContainer
    {
        readonly List<YarnProject> _projects;
        readonly List<YarnProjectContainer> _containers;

        /// <summary>
        /// Object representing a sets of YarnProjects, that may contain one or multiple projects containers..
        /// </summary>
        public YarnProjectContainer()
        {
            _projects = new List<YarnProject>();
            _containers = new List<YarnProjectContainer>();
        }

        /// <summary>
        /// Gets the projects of this container.
        /// </summary>
        public IReadOnlyList<YarnProject> SimpleProjects => _projects;

        /// <summary>
        /// Gets the projects of this container that can be published.
        /// </summary>
        public IEnumerable<YarnPublishedProject> SimplePublishedProjects => SimpleProjects.OfType<YarnPublishedProject>();

        /// <summary>
        /// Gets the Container stored in this container.
        /// </summary>
        public IReadOnlyList<YarnProjectContainer> Containers => _containers;

        /// <summary>
        /// Return All the projects, including All the projects of the <see cref="Containers"/>.
        /// </summary>
        public IEnumerable<YarnProject> AllProjects => SimpleProjects.Concat( Containers.SelectMany( s => s.AllProjects ) );

        /// <summary>
        /// Return All the <see cref="YarnProject"/> that are <see cref="YarnPublishedProject"/>, including All the projects that can be published in the <see cref="Containers"/>.
        /// </summary>
        public IEnumerable<YarnPublishedProject> AllPublishedProjects => SimplePublishedProjects.Concat( Containers.SelectMany( s => s.AllPublishedProjects ) );

        public void Add( YarnProject project )
        {
            if( _projects.Contains( project ) ) throw new InvalidOperationException( "Element was already present in the list." );
            _projects.Add( project );
        }

        public void Add( YarnProjectContainer container )
        {
            if( _containers.Contains( container ) ) throw new InvalidOperationException( "Element was already present in the list." );
            _containers.Add( container );
        }
    }
}
