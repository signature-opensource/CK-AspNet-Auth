using Cake.Npm;
using CK.Text;
using CSemVer;
using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Xml.Linq;

namespace CodeCake
{
    public static class StandardGlobalInfoNPMExtension
    {
        /// <summary>
        /// Adds the <see cref="NPMSolution"/> to the <paramref name="globalInfo"/>
        /// </summary>
        /// <param name="this">This global info.</param>
        /// <param name="solution">The NPM solution.</param>
        /// <returns>This info.</returns>
        public static StandardGlobalInfo AddNPM( this StandardGlobalInfo globalInfo, NPMSolution solution )
        {
            SVersion minmimalNpmVersionRequired = SVersion.Create( 6, 7, 0 );
            string npmVersion = globalInfo.Cake.NpmGetNpmVersion();
            if( SVersion.Parse( npmVersion ) < minmimalNpmVersionRequired )
            {
                globalInfo.Cake.TerminateWithError( "Outdated npm. Version older than v6.7.0 are known to fail on publish." );
            }
            globalInfo.RegisterSolution( solution );
            return globalInfo;
        }

        /// <summary>
        /// Adds the <see cref="Build.NPMArtifactType"/> for NPM based on <see cref="NPMSolution.ReadFromNPMSolutionFile"/>
        /// (projects are defined by "CodeCakeBuilder/NPMSolution.xml" file).
        /// </summary>
        /// <param name="this">This global info.</param>
        /// <returns>This info.</returns>
        public static StandardGlobalInfo AddNPM( this StandardGlobalInfo @this )
        {
            return AddNPM( @this, NPMSolution.ReadFromNPMSolutionFile( @this ) );
        }

        /// <summary>
        /// Gets the NPM solution handled by the single <see cref="Build.NPMArtifactType"/>.
        /// </summary>
        /// <param name="this">This global info.</param>
        /// <returns>The NPM solution.</returns>
        public static NPMSolution GetNPMSolution( this StandardGlobalInfo @this )
        {
            return @this.Solutions.OfType<NPMSolution>().Single();
        }

    }

    /// <summary>
    /// Encapsulates a set of <see cref="NPMProject"/> that can be <see cref="NPMPublishedProject"/>.
    /// </summary>
    public partial class NPMSolution : NPMCIWorkflow
    {
        readonly StandardGlobalInfo _globalInfo;

        /// <summary>
        /// Initiaizes a new <see cref="NPMSolution" />.
        /// </summary>
        /// <param name="projects">Set of projects.</param>
        NPMSolution( StandardGlobalInfo globalInfo, IEnumerable<NPMProject> projects, IEnumerable<AngularWorkspace> angularWorkspaces )
        {
            SimpleProjects = projects.ToArray();
            SimplePublishedProjects = SimpleProjects.OfType<NPMPublishedProject>().ToArray();
            _globalInfo = globalInfo;
            AngularWorkspaces = angularWorkspaces;
        }

        /// <summary>
        /// Gets all the NPM projects.
        /// </summary>
        public IReadOnlyList<NPMProject> SimpleProjects { get; }

        /// <summary>
        /// Gets the published projects.
        /// </summary>
        public IReadOnlyList<NPMPublishedProject> SimplePublishedProjects { get; }

        public IEnumerable<NPMProject> AllProjects => SimpleProjects.Concat( AngularWorkspaces.SelectMany( p => p.Projects ) );


        /// <summary>
        /// Gets the Angular Worskpaces.
        /// </summary>
        public IEnumerable<AngularWorkspace> AngularWorkspaces { get; }

        /// <summary>
        /// Runs "npm ci" on all <see cref="SimpleProjects"/>.
        /// </summary>
        protected override void RunNpmCI()
        {
            foreach( var p in SimpleProjects )
            {
                p.RunNpmCi();
            }
            foreach( var p in AngularWorkspaces )
            {
                p.RunNpmCI();
            }
        }

        protected override void RunClean()
        {
            foreach( var p in SimpleProjects )
            {
                p.RunClean();
            }

            foreach( var p in AngularWorkspaces )
            {
                p.RunClean();
            }
        }

        /// <summary>
        /// Runs the 'build-debug', 'build-release' or 'build' script on all <see cref="SimpleProjects"/>.
        /// </summary>
        /// <param name="globalInfo">The global information object.</param>
        /// <param name="scriptMustExist">
        /// False to only emit a warning and return false if the script doesn't exist instead of
        /// throwing an exception.
        /// </param>
        public virtual void RunBuild( bool scriptMustExist = true )
        {
            foreach( var p in SimpleProjects )
            {
                p.RunBuild( scriptMustExist );
            }

            foreach( var p in AngularWorkspaces )
            {
                p.Build();
            }
        }

        public override void Build() => RunBuild( true );


        /// <summary>
        /// Runs the 'test' script on all <see cref="SimpleProjects"/>.
        /// </summary>
        /// <param name="globalInfo">The global information object.</param>
        /// <param name="globalInfo"></param>
        /// <param name="scriptMustExist">
        /// False to only emit a warning and return false if the script doesn't exist instead of
        /// throwing an exception.
        /// </param>
        public virtual void RunTest( bool scriptMustExist = true )
        {
            foreach( var p in SimpleProjects )
            {
                p.RunTest( scriptMustExist );
            }
            foreach( var p in AngularWorkspaces )
            {
                p.Test();
            }
        }

        public override void Test() => RunTest( true );

        /// <summary>
        /// Generates the .tgz file in the <see cref="StandardGlobalInfo.ReleasesFolder"/>
        /// by calling npm pack for all <see cref="SimplePublishedProjects"/>.
        /// </summary>
        /// <param name="globalInfo">The global information object.</param>
        /// <param name="cleanupPackageJson">
        /// By default, "scripts" and "devDependencies" are removed from the package.json file.
        /// </param>
        /// <param name="packageJsonPreProcessor">Optional package.json pre processor.</param>
        public void RunPack( Action<JObject> packageJsonPreProcessor = null )
        {
            foreach( var p in SimplePublishedProjects )
            {
                p.RunPack( packageJsonPreProcessor );
            }

            foreach( var p in AngularWorkspaces )
            {

            }
        }

        /// <summary>
        /// Reads the "CodeCakeBuilder/NPMSolution.xml" file that must exist.
        /// </summary>
        /// <param name="version">The version of all published packages.</param>
        /// <returns>The solution object.</returns>
        public static NPMSolution ReadFromNPMSolutionFile( StandardGlobalInfo globalInfo )
        {
            var document = XDocument.Load( "CodeCakeBuilder/NPMSolution.xml" ).Root;
            var angularWorkspaces = document
                            .Elements( "AngularWorkspace" )
                            .Select( p => AngularWorkspace.Create( globalInfo, new NormalizedPath( (string)p.Attribute( "Path" ) ) ) );
            var projects = document
                            .Elements( "Project" )
                            .Select( p => (bool)p.Attribute( "IsPublished" )
                                            ? NPMPublishedProject.Load(
                                                globalInfo,
                                                (string)p.Attribute( "Path" ),
                                                (string)p.Attribute( "ExpectedName" )
                                            )
                                            : new NPMProject(
                                                globalInfo,
                                                SimplePackageJsonFile.Create( (string)p.Attribute( "Path" ) ) ) );
            return new NPMSolution( globalInfo, projects, angularWorkspaces );
        }
    }
}
